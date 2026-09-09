#!/usr/bin/env bash
# clone-cert.sh
#
# Controlled X.509 chain inspection and validation.
#
# The public remote-capture interface is always host:port. Transport selection
# is deterministic for standard ports and defaults to direct TLS otherwise.

set -euo pipefail
IFS=$'\n\t'
umask 077

readonly TOOL_NAME="clone-cert.sh"
readonly TOOL_VERSION="1.0"

WORK_DIR=""
SELFTEST_DIR=""
CAPTURE_DIR=""
APPLY_DIR=""
CLONE_PROFILE_FILE=""
AUTO_ISSUER_DIR=""
AUTO_ISSUER_CERT=""
AUTO_ISSUER_KEY=""
AUTO_ISSUER_SUBJECT=""
SELFTEST_SERVER_PID=""
declare -a CERT_FILES=()

cleanup() {
    if [[ -n "${SELFTEST_SERVER_PID}" ]]; then
        kill "${SELFTEST_SERVER_PID}" 2>/dev/null || true
        wait "${SELFTEST_SERVER_PID}" 2>/dev/null || true
    fi
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        rm -rf -- "${WORK_DIR}"
    fi
    if [[ -n "${SELFTEST_DIR}" && -d "${SELFTEST_DIR}" ]]; then
        rm -rf -- "${SELFTEST_DIR}"
    fi
    if [[ -n "${CAPTURE_DIR}" && -d "${CAPTURE_DIR}" ]]; then
        rm -rf -- "${CAPTURE_DIR}"
    fi
    if [[ -n "${APPLY_DIR}" && -d "${APPLY_DIR}" ]]; then
        rm -rf -- "${APPLY_DIR}"
    fi
    if [[ -n "${CLONE_PROFILE_FILE}" && -f "${CLONE_PROFILE_FILE}" ]]; then
        rm -f -- "${CLONE_PROFILE_FILE}"
    fi
    if [[ -n "${AUTO_ISSUER_DIR}" && -d "${AUTO_ISSUER_DIR}" ]]; then
        rm -rf -- "${AUTO_ISSUER_DIR}"
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
Usage:
  clone-cert.sh inspect --chain <bundle.pem> [--format text|json]
  clone-cert.sh fields --chain <bundle.pem>
  clone-cert.sh validate --chain <bundle.pem>
  clone-cert.sh <host:port> [--sni <name>] [--timeout-seconds <1..60>] --out-dir <directory>
  clone-cert.sh clone --chain <bundle.pem> [--issuer-cert <issuer.pem> --issuer-key <issuer.key> [--issuer-chain <bundle.pem>]] [--fake-issuer-subject <RFC4514-DN>] [--self-signed] [--original-issuer-only] [--leaf-key <leaf.key>] [--key-algorithm <rsa:bits|ec:p256|ec:p384|ed25519>] [--set-leaf-subject <RFC4514-DN>] [--set-leaf-san <DNS>] [--set-validity-days <1..90>] [--set-field <path>=<value>] [--dry-run] --out-dir <directory>
  clone-cert.sh --self-test
  clone-cert.sh --help
  clone-cert.sh --version

Commands:
  inspect   Inventory every PEM certificate in a local bundle (leaf to root).
  fields    Display the complete decoded fields and extensions of a local chain.
  validate  Check the presented chain's DN links, issuer CA constraints,
            signatures, and current validity.
  host:port Capture every certificate presented by an authorized endpoint.
            Standard ports select TLS, STARTTLS, or DTLS automatically.
  clone     Automatically creates a self-signed clone or a generated-issuer
            clone. Supplied issuer material takes precedence. --dry-run
            creates no output artifacts.
  --self-test  Generate ephemeral test certificates and run regression tests.

The input bundle must contain PEM certificates in TLS order: leaf first,
followed by zero or more intermediates and an optional root.

Standard transport mapping: 443/636/993/465 direct TLS; 25/587 SMTP STARTTLS;
143 IMAP STARTTLS; 110 POP3 STARTTLS; 389 LDAP STARTTLS; 5222/5269 XMPP
STARTTLS; 4433 DTLS. Other ports use direct TLS.
EOF
}

die() {
    local code="$1"
    shift
    printf 'error: %s\n' "$*" >&2
    exit "${code}"
}

require_openssl() {
    command -v openssl >/dev/null 2>&1 || die 1 "OpenSSL was not found in PATH"
    openssl version >/dev/null 2>&1 || die 1 "OpenSSL is not usable"
}

new_work_dir() {
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert.XXXXXX")" || die 1 "could not create a temporary directory"
}

json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "${value}"
}

trim_prefix() {
    local value="$1"
    local prefix="$2"
    printf '%s' "${value#"${prefix}"}"
}

certificate_name() {
    local cert="$1"
    local kind="$2"
    local line
    line="$(openssl x509 -in "${cert}" -noout "-${kind}" -nameopt RFC2253 2>/dev/null)" \
        || die 2 "cannot read ${kind} from certificate"
    trim_prefix "${line}" "${kind}="
}

certificate_field() {
    local cert="$1"
    local option="$2"
    openssl x509 -in "${cert}" -noout "-${option}" 2>/dev/null \
        || die 2 "cannot read ${option} from certificate"
}

certificate_sha256_fingerprint() {
    local cert="$1"
    local line
    line="$(openssl x509 -in "${cert}" -noout -sha256 -fingerprint 2>/dev/null)" \
        || die 2 "cannot read SHA-256 fingerprint from certificate"
    printf '%s' "${line#*=}"
}

certificate_is_ca() {
    local cert="$1"
    local extension
    extension="$(openssl x509 -in "${cert}" -noout -ext basicConstraints 2>/dev/null || true)"
    [[ "${extension}" == *"CA:TRUE"* ]]
}

certificate_has_ca_signing() {
    local cert="$1"
    local extension
    extension="$(openssl x509 -in "${cert}" -noout -ext keyUsage 2>/dev/null || true)"
    [[ "${extension}" == *"Certificate Sign"* ]]
}

certificate_sans() {
    local cert="$1"
    local extension
    extension="$(openssl x509 -in "${cert}" -noout -ext subjectAltName 2>/dev/null || true)"
    if [[ -z "${extension}" || "${extension}" == *"No extensions in certificate"* ]]; then
        printf '%s' ""
        return 0
    fi
    printf '%s' "${extension#*$'\n'}"
}

split_pem_bundle() {
    local bundle="$1"
    local line=""
    local current=""
    local index=0
    local in_certificate=false

    [[ -f "${bundle}" ]] || die 1 "chain file does not exist: ${bundle}"
    CERT_FILES=()
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        rm -rf -- "${WORK_DIR}"
        WORK_DIR=""
    fi
    new_work_dir

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == "-----BEGIN CERTIFICATE-----" ]]; then
            [[ "${in_certificate}" == false ]] || die 2 "nested PEM certificate header in ${bundle}"
            current="${WORK_DIR}/cert-${index}.pem"
            : >"${current}"
            in_certificate=true
        fi

        if [[ "${in_certificate}" == true ]]; then
            printf '%s\n' "${line}" >>"${current}"
        fi

        if [[ "${line}" == "-----END CERTIFICATE-----" ]]; then
            [[ "${in_certificate}" == true ]] || die 2 "PEM certificate footer without header in ${bundle}"
            openssl x509 -in "${current}" -noout >/dev/null 2>&1 \
                || die 2 "invalid PEM certificate at position ${index}"
            CERT_FILES+=("${current}")
            index=$((index + 1))
            in_certificate=false
        fi
    done <"${bundle}"

    [[ "${in_certificate}" == false ]] || die 2 "unterminated PEM certificate in ${bundle}"
    ((${#CERT_FILES[@]} > 0)) || die 2 "no PEM certificates found in ${bundle}"
}

print_certificate_text() {
    local cert="$1"
    local index="$2"
    local subject issuer serial start_date end_date fingerprint san ca_state

    subject="$(certificate_name "${cert}" subject)"
    issuer="$(certificate_name "${cert}" issuer)"
    serial="$(trim_prefix "$(certificate_field "${cert}" serial)" "serial=")"
    start_date="$(trim_prefix "$(certificate_field "${cert}" startdate)" "notBefore=")"
    end_date="$(trim_prefix "$(certificate_field "${cert}" enddate)" "notAfter=")"
    fingerprint="$(certificate_sha256_fingerprint "${cert}")"
    san="$(certificate_sans "${cert}")"
    ca_state=false
    certificate_is_ca "${cert}" && ca_state=true

    printf 'Certificate %s\n' "${index}"
    printf '  Subject: %s\n' "${subject}"
    printf '  Issuer: %s\n' "${issuer}"
    printf '  Serial: %s\n' "${serial}"
    printf '  SHA-256: %s\n' "${fingerprint}"
    printf '  Not before: %s\n' "${start_date}"
    printf '  Not after: %s\n' "${end_date}"
    printf '  CA: %s\n' "${ca_state}"
    [[ -z "${san}" ]] || printf '  Subject alternative names: %s\n' "${san}"
}

print_certificate_json() {
    local cert="$1"
    local index="$2"
    local subject issuer serial start_date end_date fingerprint san ca_state

    subject="$(certificate_name "${cert}" subject)"
    issuer="$(certificate_name "${cert}" issuer)"
    serial="$(trim_prefix "$(certificate_field "${cert}" serial)" "serial=")"
    start_date="$(trim_prefix "$(certificate_field "${cert}" startdate)" "notBefore=")"
    end_date="$(trim_prefix "$(certificate_field "${cert}" enddate)" "notAfter=")"
    fingerprint="$(certificate_sha256_fingerprint "${cert}")"
    san="$(certificate_sans "${cert}")"
    ca_state=false
    certificate_is_ca "${cert}" && ca_state=true

    printf '  {\n'
    printf '    "position": %s,\n' "${index}"
    printf '    "subject": "%s",\n' "$(json_escape "${subject}")"
    printf '    "issuer": "%s",\n' "$(json_escape "${issuer}")"
    printf '    "serial": "%s",\n' "$(json_escape "${serial}")"
    printf '    "sha256": "%s",\n' "$(json_escape "${fingerprint}")"
    printf '    "not_before": "%s",\n' "$(json_escape "${start_date}")"
    printf '    "not_after": "%s",\n' "$(json_escape "${end_date}")"
    printf '    "is_ca": %s,\n' "${ca_state}"
    printf '    "subject_alt_name": "%s"\n' "$(json_escape "${san}")"
    printf '  }'
}

cmd_inspect() {
    local chain=""
    local output_format="text"
    local index

    while (($# > 0)); do
        case "$1" in
            --chain)
                (($# >= 2)) || die 1 "--chain requires a file path"
                chain="$2"
                shift 2
                ;;
            --format)
                (($# >= 2)) || die 1 "--format requires text or json"
                output_format="$2"
                shift 2
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown inspect option: $1"
                ;;
        esac
    done

    [[ -n "${chain}" ]] || die 1 "inspect requires --chain <bundle.pem>"
    [[ "${output_format}" == "text" || "${output_format}" == "json" ]] \
        || die 1 "--format must be text or json"
    require_openssl
    split_pem_bundle "${chain}"

    if [[ "${output_format}" == "json" ]]; then
        printf '[\n'
        for index in "${!CERT_FILES[@]}"; do
            print_certificate_json "${CERT_FILES[index]}" "${index}"
            ((index + 1 < ${#CERT_FILES[@]})) && printf ','
            printf '\n'
        done
        printf ']\n'
    else
        for index in "${!CERT_FILES[@]}"; do
            print_certificate_text "${CERT_FILES[index]}" "${index}"
        done
    fi
}

cmd_fields() {
    local chain=""
    local index

    while (($# > 0)); do
        case "$1" in
            --chain)
                (($# >= 2)) || die 1 "--chain requires a file path"
                chain="$2"
                shift 2
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown fields option: $1"
                ;;
        esac
    done
    [[ -n "${chain}" ]] || die 1 "fields requires --chain <bundle.pem>"
    require_openssl
    split_pem_bundle "${chain}"
    for index in "${!CERT_FILES[@]}"; do
        printf 'Certificate %s complete decoded fields\n' "${index}"
        openssl x509 -in "${CERT_FILES[index]}" -noout -text \
            || die 2 "could not decode certificate ${index}"
    done
}

validate_link() {
    local child="$1"
    local issuer="$2"
    local index="$3"
    local child_issuer issuer_subject

    child_issuer="$(certificate_name "${child}" issuer)"
    issuer_subject="$(certificate_name "${issuer}" subject)"
    [[ "${child_issuer}" == "${issuer_subject}" ]] \
        || die 2 "chain link ${index}: issuer DN does not match the next certificate subject"
    certificate_is_ca "${issuer}" \
        || die 2 "chain link ${index}: issuer certificate is not a CA"
    certificate_has_ca_signing "${issuer}" \
        || die 2 "chain link ${index}: issuer certificate lacks Certificate Sign key usage"
    openssl verify -no-CApath -no-CAfile -partial_chain -CAfile "${issuer}" "${child}" >/dev/null 2>&1 \
        || die 2 "chain link ${index}: signature or validity verification failed"
}

cmd_validate() {
    local chain=""
    local index last root_subject root_issuer

    while (($# > 0)); do
        case "$1" in
            --chain)
                (($# >= 2)) || die 1 "--chain requires a file path"
                chain="$2"
                shift 2
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown validate option: $1"
                ;;
        esac
    done

    [[ -n "${chain}" ]] || die 1 "validate requires --chain <bundle.pem>"
    require_openssl
    split_pem_bundle "${chain}"

    for index in "${!CERT_FILES[@]}"; do
        if ((index + 1 < ${#CERT_FILES[@]})); then
            validate_link "${CERT_FILES[index]}" "${CERT_FILES[index + 1]}" "${index}"
        fi
    done

    last=$((${#CERT_FILES[@]} - 1))
    root_subject="$(certificate_name "${CERT_FILES[last]}" subject)"
    root_issuer="$(certificate_name "${CERT_FILES[last]}" issuer)"
    if [[ "${root_subject}" == "${root_issuer}" ]]; then
        if ((${#CERT_FILES[@]} > 1)); then
            certificate_is_ca "${CERT_FILES[last]}" || die 2 "root certificate is not a CA"
            certificate_has_ca_signing "${CERT_FILES[last]}" || die 2 "root certificate lacks Certificate Sign key usage"
        fi
        openssl verify -no-CApath -no-CAfile -CAfile "${CERT_FILES[last]}" "${CERT_FILES[last]}" >/dev/null 2>&1 \
            || die 2 "self-signed final certificate failed signature or validity verification"
        printf 'valid: %s certificate(s), complete self-signed root\n' "${#CERT_FILES[@]}"
    else
        certificate_is_ca "${CERT_FILES[last]}" || die 2 "final presented certificate is not a CA"
        certificate_has_ca_signing "${CERT_FILES[last]}" || die 2 "final presented certificate lacks Certificate Sign key usage"
        printf 'valid links: %s certificate(s); warning: no self-signed root was presented\n' "${#CERT_FILES[@]}"
    fi
}

parse_connect_target() {
    local target="$1"
    local host=""
    local port=""

    if [[ "${target}" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    elif [[ "${target}" =~ ^([^:[:space:]]+):([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    else
        die 1 "target must use host:port or [ipv6]:port"
    fi

    ((10#${port} >= 1 && 10#${port} <= 65535)) || die 1 "target port must be between 1 and 65535"
    printf '%s\n%s' "${host}" "${port}"
}

validate_output_dir() {
    local output_dir="$1"
    local -a entries=()

    [[ ! -L "${output_dir}" ]] || die 1 "--out-dir must not be a symbolic link"
    if [[ -e "${output_dir}" ]]; then
        [[ -d "${output_dir}" ]] || die 1 "--out-dir exists but is not a directory: ${output_dir}"
        shopt -s nullglob dotglob
        entries=("${output_dir}"/*)
        shopt -u nullglob dotglob
        ((${#entries[@]} == 0)) || die 1 "--out-dir must be empty: ${output_dir}"
    fi
}

validate_capture_base_dir() {
    local output_dir="$1"

    [[ ! -L "${output_dir}" ]] || die 1 "--out-dir must not be a symbolic link"
    if [[ -e "${output_dir}" ]]; then
        [[ -d "${output_dir}" ]] || die 1 "--out-dir exists but is not a directory: ${output_dir}"
    else
        mkdir -p -- "${output_dir}" || die 1 "could not create --out-dir: ${output_dir}"
    fi
}

safe_capture_name() {
    local value="$1"
    value="$(printf '%s' "${value}" | sed 's/[^A-Za-z0-9._-]/-/g; s/--*/-/g; s/^-//; s/-$//')"
    [[ -n "${value}" ]] || value='certificate'
    printf '%s' "${value}"
}

create_capture_dir() {
    local base_dir="$1"
    local cert="$2"
    local host="$3"
    local port="$4"
    local cn slug timestamp fingerprint suffix candidate

    cn="$(subject_common_name "$(certificate_name "${cert}" subject)")" || cn="${host}"
    slug="$(safe_capture_name "${cn}")"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    fingerprint="$(certificate_sha256_fingerprint "${cert}")"
    fingerprint="${fingerprint//:/}"
    fingerprint="${fingerprint:0:12}"
    for suffix in '' '-2' '-3' '-4' '-5'; do
        candidate="${base_dir}/${slug}-${port}-${timestamp}-${fingerprint}${suffix}"
        if [[ ! -e "${candidate}" && ! -L "${candidate}" ]]; then
            mkdir -- "${candidate}" || die 1 "could not create capture directory: ${candidate}"
            printf '%s' "${candidate}"
            return 0
        fi
    done
    die 1 "could not allocate a unique capture directory under: ${base_dir}"
}

write_capture_manifest() {
    local output_dir="$1"
    local target="$2"
    local sni="$3"
    local timeout_seconds="$4"
    local transport="$5"
    local manifest="${output_dir}/manifest.json"
    local index fingerprint

    {
        printf '{\n'
        printf '  "operation": "x509-capture",\n'
        printf '  "connect": "%s",\n' "$(json_escape "${target}")"
        printf '  "transport": "%s",\n' "$(json_escape "${transport}")"
        printf '  "sni": "%s",\n' "$(json_escape "${sni}")"
        printf '  "timeout_seconds": %s,\n' "${timeout_seconds}"
        printf '  "certificate_count": %s,\n' "${#CERT_FILES[@]}"
        printf '  "certificates_sha256": [\n'
        for index in "${!CERT_FILES[@]}"; do
            fingerprint="$(certificate_sha256_fingerprint "${CERT_FILES[index]}")"
            printf '    "%s"' "$(json_escape "${fingerprint}")"
            ((index + 1 < ${#CERT_FILES[@]})) && printf ','
            printf '\n'
        done
        printf '  ]\n'
        printf '}\n'
    } >"${manifest}"
}

transport_for_port() {
    local port="$1"
    case "${port}" in
        443|636|993|465) printf 'tls' ;;
        25|587) printf 'starttls-smtp' ;;
        143) printf 'starttls-imap' ;;
        110) printf 'starttls-pop3' ;;
        389) printf 'starttls-ldap' ;;
        5222|5269) printf 'starttls-xmpp' ;;
        4433) printf 'dtls' ;;
        *) printf 'tls' ;;
    esac
}

run_capture_client() {
    local connect="$1"
    local transport="$2"
    local raw_capture="$3"
    local stderr_capture="$4"
    local timeout_seconds="$5"
    shift 5
    local pid start_seconds
    local -a transport_options=("$@")

    openssl s_client -showcerts -connect "${connect}" "${transport_options[@]}" \
        < /dev/null >"${raw_capture}" 2>"${stderr_capture}" &
    pid=$!
    start_seconds=${SECONDS}
    while kill -0 "${pid}" 2>/dev/null; do
        if ((SECONDS - start_seconds >= timeout_seconds)); then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
            die 1 "${transport} connection timed out after ${timeout_seconds} seconds"
        fi
        sleep 1
    done
    wait "${pid}" || die 1 "${transport} connection failed: $(<"${stderr_capture}")"
}

cmd_capture() {
    local connect=""
    local sni=""
    local timeout_seconds=10
    local output_dir=""
    local parsed_target host port raw_capture stderr_capture index transport capture_dir capture_name
    local -a client_options=()

    while (($# > 0)); do
        case "$1" in
            --sni)
                (($# >= 2)) || die 1 "--sni requires a server name"
                sni="$2"
                shift 2
                ;;
            --timeout-seconds)
                (($# >= 2)) || die 1 "--timeout-seconds requires a value"
                timeout_seconds="$2"
                shift 2
                ;;
            --out-dir)
                (($# >= 2)) || die 1 "--out-dir requires a directory"
                output_dir="$2"
                shift 2
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                if [[ -z "${connect}" && "$1" != -* ]]; then
                    connect="$1"
                    shift
                else
                    die 1 "unknown capture option: $1"
                fi
                ;;
        esac
    done

    [[ -n "${connect}" ]] || die 1 "capture requires host:port"
    [[ -n "${output_dir}" ]] || die 1 "capture requires --out-dir <directory>"
    [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] \
        || die 1 "--timeout-seconds must be an integer between 1 and 60"
    ((10#${timeout_seconds} >= 1 && 10#${timeout_seconds} <= 60)) \
        || die 1 "--timeout-seconds must be between 1 and 60"
    if [[ -n "${sni}" ]]; then
        [[ "${sni}" =~ ^[A-Za-z0-9.-]+$ && "${sni}" != .* && "${sni}" != *..* ]] \
            || die 1 "--sni must be a DNS name without whitespace"
        client_options+=(-servername "${sni}")
    fi

    require_openssl
    validate_capture_base_dir "${output_dir}"
    parsed_target="$(parse_connect_target "${connect}")"
    host="${parsed_target%%$'\n'*}"
    port="${parsed_target#*$'\n'}"
    transport="$(transport_for_port "${port}")"
    case "${transport}" in
        starttls-smtp) client_options+=(-starttls smtp) ;;
        starttls-imap) client_options+=(-starttls imap) ;;
        starttls-pop3) client_options+=(-starttls pop3) ;;
        starttls-ldap) client_options+=(-starttls ldap) ;;
        starttls-xmpp) client_options+=(-starttls xmpp) ;;
        dtls) client_options+=(-dtls) ;;
    esac
    CAPTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert-capture.XXXXXX")" \
        || die 1 "could not create a capture directory"
    raw_capture="${CAPTURE_DIR}/s-client-output.txt"
    stderr_capture="${CAPTURE_DIR}/s-client-error.txt"

    printf 'Connecting to %s:%s using %s%s (timeout: %ss)\n' \
        "${host}" "${port}" "${transport}" "${sni:+, SNI: ${sni}}" "${timeout_seconds}"
    run_capture_client "${connect}" "${transport}" "${raw_capture}" "${stderr_capture}" \
        "${timeout_seconds}" "${client_options[@]}"

    split_pem_bundle "${raw_capture}"
    printf 'Captured %s certificate(s); review before saving:\n' "${#CERT_FILES[@]}"
    for index in "${!CERT_FILES[@]}"; do
        print_certificate_text "${CERT_FILES[index]}" "${index}"
    done

    capture_dir="$(create_capture_dir "${output_dir}" "${CERT_FILES[0]}" "${host}" "${port}")"
    capture_name="$(subject_common_name "$(certificate_name "${CERT_FILES[0]}" subject)")" || capture_name="${host}"
    capture_name="$(safe_capture_name "${capture_name}")"
    {
        for index in "${!CERT_FILES[@]}"; do
            append_file "${CERT_FILES[index]}"
        done
    } >"${capture_dir}/${capture_name}-chain.pem" || {
        rm -f -- "${capture_dir}/${capture_name}-chain.pem"
        die 1 "could not save captured certificate chain"
    }
    write_capture_manifest "${capture_dir}" "${connect}" "${sni}" "${timeout_seconds}" "${transport}" || {
        rm -f -- "${capture_dir}/${capture_name}-chain.pem" "${capture_dir}/manifest.json"
        die 1 "could not save capture manifest"
    }
    printf 'Saved capture to %s\n' "${capture_dir}"
}

certificate_dns_sans() {
    local cert="$1"
    local extension remainder name
    extension="$(certificate_sans "${cert}")"
    remainder="${extension}"
    while [[ "${remainder}" =~ DNS:([^,[:space:]]+) ]]; do
        name="${BASH_REMATCH[1]}"
        printf '%s\n' "${name}"
        remainder="${remainder#*"DNS:${name}"}"
    done
}

print_json_string_array() {
    local index
    local -a values=("$@")
    printf '['
    for index in "${!values[@]}"; do
        printf '"%s"' "$(json_escape "${values[index]}")"
        ((index + 1 < ${#values[@]})) && printf ','
    done
    printf ']'
}

validate_dns_name() {
    local name="$1"
    [[ "${name}" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
        || die 3 "DNS name is invalid: ${name}"
}

subject_common_name() {
    local subject="$1"
    if [[ "${subject}" =~ (^|,)CN=([^,]+) ]]; then
        printf '%s' "${BASH_REMATCH[2]}"
    else
        return 1
    fi
}

replace_subject_attribute() {
    local subject="$1"
    local attribute="$2"
    local value="$3"
    local index joined="" found=false
    local saved_ifs="${IFS}"
    local -a rdns=()

    [[ "${subject}" != *'\,'* ]] || return 2
    IFS=',' read -r -a rdns <<<"${subject}"
    IFS="${saved_ifs}"
    for index in "${!rdns[@]}"; do
        if [[ "${rdns[index]%%=*}" == "${attribute}" ]]; then
            rdns[index]="${attribute}=${value}"
            found=true
            break
        fi
    done
    [[ "${found}" == true ]] || rdns+=("${attribute}=${value}")
    for index in "${!rdns[@]}"; do
        [[ -z "${joined}" ]] || joined+=','
        joined+="${rdns[index]}"
    done
    printf '%s' "${joined}"
}

write_clone_profile() {
    local destination="$1"
    local source_subject="$2"
    local final_subject="$3"
    local subject_provenance="$4"
    local san_provenance="$5"
    local source_not_before="$6"
    local source_not_after="$7"
    local validity_days="$8"
    local validity_provenance="$9"
    local overrides_file="${10}"
    shift 10
    local index fingerprint
    local -a source_sans=()
    local -a final_sans=()
    local -a source_hashes=()

    while [[ "$1" != "--" ]]; do
        source_sans+=("$1")
        shift
    done
    shift
    while [[ "$1" != "--" ]]; do
        final_sans+=("$1")
        shift
    done
    shift
    for index in "${!CERT_FILES[@]}"; do
        fingerprint="$(certificate_sha256_fingerprint "${CERT_FILES[index]}")"
        source_hashes+=("${fingerprint}")
    done

    {
        printf '{\n'
        printf '  "schema_version": 1,\n'
        printf '  "tool_version": "%s",\n' "$(json_escape "${TOOL_VERSION}")"
        printf '  "operation": "profile-preserving-reissue",\n'
        printf '  "source": {\n'
        printf '    "certificate_count": %s,\n' "${#CERT_FILES[@]}"
        printf '    "chain_sha256": '
        print_json_string_array "${source_hashes[@]}"
        printf '\n  },\n'
        printf '  "fields": {\n'
        printf '    "leaf_subject": {"source": "%s", "final": "%s", "provenance": "%s"},\n' \
            "$(json_escape "${source_subject}")" "$(json_escape "${final_subject}")" "${subject_provenance}"
        printf '    "leaf_dns_sans": {"source": '
        print_json_string_array "${source_sans[@]}"
        printf ', "final": '
        print_json_string_array "${final_sans[@]}"
        printf ', "provenance": "%s"},\n' "${san_provenance}"
        printf '    "validity": {"source_not_before": "%s", "source_not_after": "%s", "requested_days": ' \
            "$(json_escape "${source_not_before}")" "$(json_escape "${source_not_after}")"
        if [[ -n "${validity_days}" ]]; then
            printf '%s' "${validity_days}"
        else
            printf 'null'
        fi
        printf ', "provenance": "%s"}\n' "${validity_provenance}"
        printf '  },\n'
        printf '  "requested_overrides": '
        append_file "${overrides_file}"
        printf ',\n'
        printf '  "derived_fields": ["issuer", "serial", "subject_public_key_info", "subject_key_identifier", "authority_key_identifier", "signature"],\n'
        printf '  "policy": {"dns_name_validation": "syntax-only"}\n'
        printf '}\n'
    } >"${destination}"
}

prepare_clone_profile() {
    local chain=""
    local profile=""
    local requested_subject=""
    local requested_validity_days=""
    local source_subject final_subject subject_provenance
    local source_not_before source_not_after validity_provenance
    local san_provenance
    local payload overrides_file profile_hash index name output_parent
    local -a source_sans=()
    local -a requested_sans=()
    local -a final_sans=()
    local -a requested_subject_attributes=()
    local field_path field_value field_attribute saved_ifs
    local -a field_sans=()

    while (($# > 0)); do
        case "$1" in
            --chain)
                (($# >= 2)) || die 1 "--chain requires a file path"
                chain="$2"
                shift 2
                ;;
            --profile)
                (($# >= 2)) || die 1 "--profile requires a file path"
                profile="$2"
                shift 2
                ;;
            --set-leaf-subject)
                (($# >= 2)) || die 1 "--set-leaf-subject requires an RFC4514 DN"
                [[ -z "${requested_subject}" ]] || die 3 "--set-leaf-subject may be used once"
                requested_subject="$2"
                shift 2
                ;;
            --set-leaf-san)
                (($# >= 2)) || die 1 "--set-leaf-san requires a DNS name"
                ((${#field_sans[@]} == 0)) \
                    || die 3 "--set-leaf-san cannot be combined with --set-field san.dns"
                requested_sans+=("$2")
                shift 2
                ;;
            --set-validity-days)
                (($# >= 2)) || die 1 "--set-validity-days requires a value"
                [[ -z "${requested_validity_days}" ]] \
                    || die 3 "--set-validity-days cannot be combined with validity.days"
                requested_validity_days="$2"
                shift 2
                ;;
            --set-field)
                (($# >= 2)) || die 1 "--set-field requires <path>=<value>"
                [[ "$2" == *=* ]] || die 3 "--set-field requires <path>=<value>"
                field_path="${2%%=*}"
                field_value="${2#*=}"
                [[ -n "${field_value}" ]] || die 3 "--set-field value must not be empty; use --unset-field when available"
                case "${field_path}" in
                    subject.*)
                        field_attribute="${field_path#subject.}"
                        [[ "${field_attribute}" =~ ^[A-Za-z][A-Za-z0-9]*$ ]] \
                            || die 3 "unsupported Subject attribute path: ${field_path}"
                        [[ "${field_value}" != *','* && "${field_value}" != *$'\n'* && "${field_value}" != *$'\r'* ]] \
                            || die 3 "Subject attribute values may not contain commas or newlines in this increment"
                        requested_subject_attributes+=("${field_attribute}=${field_value}")
                        ;;
                    san.dns)
                        ((${#requested_sans[@]} == 0 && ${#field_sans[@]} == 0)) \
                            || die 3 "--set-field san.dns cannot be combined with another SAN override"
                        saved_ifs="${IFS}"
                        IFS=';' read -r -a field_sans <<<"${field_value}"
                        IFS="${saved_ifs}"
                        ((${#field_sans[@]} > 0)) || die 3 "san.dns requires one or more semicolon-separated DNS names"
                        ;;
                    validity.days)
                        [[ -z "${requested_validity_days}" ]] \
                            || die 3 "validity.days cannot be specified more than once"
                        requested_validity_days="${field_value}"
                        ;;
                    *)
                        die 3 "unsupported field path: ${field_path}; supported paths are subject.<attribute>, san.dns and validity.days"
                        ;;
                esac
                shift 2
                ;;
            --unset-field|--set-extension|--remove-extension)
                die 3 "$1 is not supported by the current clone profile"
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown internal clone-profile option: $1"
                ;;
        esac
    done

    [[ -n "${chain}" && -n "${profile}" ]] \
        || die 1 "internal clone-profile preparation requires --chain and --profile"
    [[ -z "${requested_subject}" || ${#requested_subject_attributes[@]} == 0 ]] \
        || die 3 "--set-leaf-subject cannot be combined with --set-field subject.<attribute>"
    if [[ -n "${profile}" ]]; then
        [[ ! -e "${profile}" ]] || die 1 "internal clone profile already exists: ${profile}"
        if [[ "${profile}" == */* ]]; then
            output_parent="${profile%/*}"
            [[ -n "${output_parent}" ]] || output_parent="/"
        else
            output_parent="."
        fi
        [[ -d "${output_parent}" ]] || die 1 "parent directory for internal profile does not exist: ${output_parent}"
    fi
    if [[ -n "${requested_validity_days}" ]]; then
        [[ "${requested_validity_days}" =~ ^[0-9]+$ ]] \
            || die 3 "--set-validity-days must be an integer between 1 and 90"
        ((10#${requested_validity_days} >= 1 && 10#${requested_validity_days} <= 90)) \
            || die 3 "--set-validity-days must be between 1 and 90"
    fi

    require_openssl
    split_pem_bundle "${chain}"
    source_subject="$(certificate_name "${CERT_FILES[0]}" subject)"
    source_not_before="$(trim_prefix "$(certificate_field "${CERT_FILES[0]}" startdate)" "notBefore=")"
    source_not_after="$(trim_prefix "$(certificate_field "${CERT_FILES[0]}" enddate)" "notAfter=")"
    while IFS= read -r name; do
        [[ -z "${name}" ]] || source_sans+=("${name}")
    done < <(certificate_dns_sans "${CERT_FILES[0]}")

    final_subject="${source_subject}"
    subject_provenance="preserved"
    if [[ -n "${requested_subject}" ]]; then
        final_subject="${requested_subject}"
        subject_provenance="overridden"
    elif ((${#requested_subject_attributes[@]} > 0)); then
        for name in "${requested_subject_attributes[@]}"; do
            field_attribute="${name%%=*}"
            field_value="${name#*=}"
            final_subject="$(replace_subject_attribute "${final_subject}" "${field_attribute}" "${field_value}")" \
                || die 3 "the source Subject uses escaped commas and cannot be edited by --set-field in this increment"
        done
        subject_provenance="overridden"
    fi
    if [[ "${subject_provenance}" == "overridden" ]]; then
        name="$(subject_common_name "${final_subject}")" \
            || die 3 "an overridden Subject must include CN=<name> in RFC4514 form"
        validate_dns_name "${name}"
    fi

    final_sans=("${source_sans[@]}")
    san_provenance="preserved"
    if ((${#field_sans[@]} > 0)); then
        requested_sans=("${field_sans[@]}")
    fi
    if ((${#requested_sans[@]} > 0)); then
        for name in "${requested_sans[@]}"; do
            validate_dns_name "${name}"
        done
        final_sans=("${requested_sans[@]}")
        san_provenance="overridden"
    fi
    validity_provenance="preserved"
    [[ -z "${requested_validity_days}" ]] || validity_provenance="overridden"

    payload="${WORK_DIR}/clone-profile.json"
    overrides_file="${WORK_DIR}/clone-overrides.json"
    printf '{}' >"${overrides_file}"
    write_clone_profile "${payload}" "${source_subject}" "${final_subject}" "${subject_provenance}" "${san_provenance}" \
        "${source_not_before}" "${source_not_after}" "${requested_validity_days}" "${validity_provenance}" "${overrides_file}" \
        "${source_sans[@]}" -- "${final_sans[@]}" --
    profile_hash="$(openssl dgst -sha256 "${payload}")"
    profile_hash="${profile_hash##*= }"

    {
        printf 'Clone profile summary:\n'
        printf '  Source certificates: %s\n' "${#CERT_FILES[@]}"
        printf '  Subject: %s → %s (%s)\n' "${source_subject}" "${final_subject}" "${subject_provenance}"
        printf '  DNS SANs: %s → %s (%s)\n' \
            "${#source_sans[@]} value(s)" "${#final_sans[@]} value(s)" "${san_provenance}"
        if [[ -n "${requested_validity_days}" ]]; then
            printf '  Validity: %s days (overridden)\n' "${requested_validity_days}"
        else
            printf '  Validity: preserved from profile\n'
        fi
        printf '  Reissued values: issuer, serial, key material, SKI, AKI, signature\n'
        printf '  Profile SHA-256: %s\n' "${profile_hash}"
    } >&2

    {
        printf '{\n  "canonical_payload": '
        append_file "${payload}"
        printf ',\n  "profile_sha256": "%s"\n}\n' "${profile_hash}"
    } >"${profile}" || die 1 "could not write internal clone profile"
}

extract_clone_profile() {
    local profile="$1"
    local destination="$2"

    awk '
        /^  "canonical_payload": \{$/ { print "{"; in_payload=1; next }
        in_payload && /^},$/ { print "}"; exit }
        in_payload { print }
    ' "${profile}" >"${destination}"
    [[ -s "${destination}" && "$(head -n 1 "${destination}")" == "{" ]] \
        || die 3 "clone profile does not contain a canonical payload"
}

verify_clone_profile_integrity() {
    local profile="$1"
    local payload="$2"
    local expected actual

    [[ -f "${profile}" && ! -L "${profile}" ]] || die 1 "internal clone profile must be a regular file"
    extract_clone_profile "${profile}" "${payload}"
    expected="$(awk -F'"' '/^  "profile_sha256": / { print $4; exit }' "${profile}")"
    [[ "${expected}" =~ ^[A-Fa-f0-9]{64}$ ]] || die 3 "clone profile SHA-256 is missing or invalid"
    actual="$(openssl dgst -sha256 "${payload}")"
    actual="${actual##*= }"
    [[ "${actual}" == "${expected}" ]] || die 3 "clone profile SHA-256 does not match its canonical payload"
    grep -Fqx '  "schema_version": 1,' "${payload}" \
        || die 3 "unsupported clone profile schema"
    grep -Fqx '  "operation": "profile-preserving-reissue",' "${payload}" \
        || die 3 "unsupported clone profile operation"
}

clone_profile_leaf_subject() {
    local payload="$1"
    awk '
        /"leaf_subject":/ {
            value=$0
            sub(/^.*"final": "/, "", value)
            sub(/", "provenance".*$/, "", value)
            print value
            exit
        }
    ' "${payload}"
}

clone_profile_validity_days() {
    local payload="$1"
    local line
    line="$(awk '/"validity":/ { print; exit }' "${payload}")"
    if [[ "${line}" =~ \"requested_days\":\ (null|[0-9]+) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        die 3 "clone profile validity field is malformed"
    fi
}

clone_profile_dns_sans() {
    local payload="$1"
    local line values name
    line="$(awk '/"leaf_dns_sans":/ { print; exit }' "${payload}")"
    values="${line#*\"final\": }"
    values="${values%%, \"provenance\"*}"
    [[ "${values}" == \[*\] ]] || die 3 "clone profile DNS SAN field is malformed"
    values="${values#[}"
    values="${values%]}"
    [[ -z "${values}" ]] && return 0
    while [[ "${values}" =~ ^\"([^\"]+)\"(,?)(.*)$ ]]; do
        name="${BASH_REMATCH[1]}"
        printf '%s\n' "${name}"
        values="${BASH_REMATCH[3]}"
    done
    [[ -z "${values}" ]] || die 3 "clone profile DNS SAN values are malformed"
}

verify_clone_profile_source_chain() {
    local payload="$1"
    local expected_count index fingerprint

    expected_count="$(awk -F': ' '/"certificate_count"/ { gsub(/,/, "", $2); print $2; exit }' "${payload}")"
    [[ "${expected_count}" =~ ^[0-9]+$ && "${expected_count}" == "${#CERT_FILES[@]}" ]] \
        || die 3 "source chain does not match the clone profile certificate count"
    for index in "${!CERT_FILES[@]}"; do
        fingerprint="$(certificate_sha256_fingerprint "${CERT_FILES[index]}")"
        grep -Fq "\"${fingerprint}\"" "${payload}" \
            || die 3 "source chain does not match the clone profile"
    done
}

rfc2253_to_openssl_subject() {
    local subject="$1"
    local saved_ifs="${IFS}"
    local rdn result="" index
    local -a rdns=()

    [[ -n "${subject}" && "${subject}" != *'\\'* && "${subject}" != *'/'* && "${subject}" != *'+'* ]] \
        || return 1
    IFS=',' read -r -a rdns <<<"${subject}"
    IFS="${saved_ifs}"
    for ((index = ${#rdns[@]} - 1; index >= 0; index--)); do
        rdn="${rdns[index]}"
        [[ "${rdn}" =~ ^[A-Za-z][A-Za-z0-9.]*=.+$ ]] || return 1
        result+="/${rdn}"
    done
    printf '%s' "${result}"
}

source_is_self_issued() {
    local cert="$1"
    [[ "$(certificate_name "${cert}" subject)" == "$(certificate_name "${cert}" issuer)" ]]
}

derive_fake_issuer_subject() {
    local subject="$1"
    local saved_ifs="${IFS}"
    local rdn attribute value result="" changed=false
    local -a rdns=()

    [[ "${subject}" != *'\\'* ]] || return 1
    IFS=',' read -r -a rdns <<<"${subject}"
    IFS="${saved_ifs}"
    for rdn in "${rdns[@]}"; do
        attribute="${rdn%%=*}"
        value="${rdn#*=}"
        [[ "${attribute}" != "${rdn}" && -n "${value}" ]] || return 1
        if [[ "${changed}" == false && "${value}" == *O* ]]; then
            value="${value/O/0}"
            changed=true
        elif [[ "${changed}" == false && "${value}" == *l* ]]; then
            value="${value/l/I}"
            changed=true
        fi
        [[ -z "${result}" ]] || result+=','
        result+="${attribute}=${value}"
    done
    if [[ "${changed}" == false ]]; then
        rdn="${result##*,}"
        attribute="${rdn%%=*}"
        value="${rdn#*=}"
        [[ "${value}" =~ . ]] || return 1
        value="${value%?} "
        if [[ "${result}" == *,* ]]; then
            result="${result%,*},${attribute}=${value}"
        else
            result="${attribute}=${value}"
        fi
    fi
    printf '%s' "${result}"
}

generate_automatic_issuer() {
    local source_issuer="$1"
    local requested_subject="$2"
    local validity_days="$3"
    local issuer_subject openssl_subject extension_config

    if [[ -n "${requested_subject}" ]]; then
        issuer_subject="${requested_subject}"
    else
        issuer_subject="$(derive_fake_issuer_subject "${source_issuer}")" \
            || die 4 "could not derive a fake issuer Subject from the source issuer; use --fake-issuer-subject"
    fi
    [[ "${issuer_subject}" != "${source_issuer}" ]] \
        || die 4 "generated issuer Subject must differ from the source issuer"
    openssl_subject="$(rfc2253_to_openssl_subject "${issuer_subject}")" \
        || die 4 "fake issuer Subject cannot be represented safely for OpenSSL issuance"
    AUTO_ISSUER_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert-generated-issuer.XXXXXX")" \
        || die 1 "could not create a generated issuer directory"
    AUTO_ISSUER_KEY="${AUTO_ISSUER_DIR}/generated-issuer.key.pem"
    AUTO_ISSUER_CERT="${AUTO_ISSUER_DIR}/generated-issuer.cert.pem"
    extension_config="${AUTO_ISSUER_DIR}/generated-issuer.cnf"
    {
        printf '[req]\n'
        printf 'distinguished_name=req_distinguished_name\n'
        printf 'prompt=no\n'
        printf '[req_distinguished_name]\n'
        printf '[v3_ca]\n'
        printf 'basicConstraints=critical,CA:TRUE,pathlen:0\n'
        printf 'keyUsage=critical,keyCertSign,cRLSign\n'
        printf 'subjectKeyIdentifier=hash\n'
    } >"${extension_config}"
    generate_leaf_key 'rsa:3072' "${AUTO_ISSUER_KEY}" \
        || die 4 "could not generate the automatic issuer private key"
    openssl req -new -x509 -key "${AUTO_ISSUER_KEY}" -subj "${openssl_subject}" \
        -days "${validity_days}" -sha256 -config "${extension_config}" -extensions v3_ca \
        -out "${AUTO_ISSUER_CERT}" >/dev/null 2>&1 \
        || die 4 "could not issue the automatic issuer certificate"
    [[ "$(certificate_name "${AUTO_ISSUER_CERT}" subject)" != "${source_issuer}" ]] \
        || die 4 "generated issuer Subject was normalised to the source issuer; use --fake-issuer-subject"
    AUTO_ISSUER_SUBJECT="${issuer_subject}"
}

remaining_validity_days() {
    local cert="$1"
    local low=0
    local high=1
    local middle

    while ((high < 365000)) && openssl x509 -in "${cert}" -noout -checkend "$((high * 86400))" >/dev/null 2>&1; do
        low=${high}
        high=$((high * 2))
    done
    while ((low + 1 < high)); do
        middle=$(((low + high) / 2))
        if openssl x509 -in "${cert}" -noout -checkend "$((middle * 86400))" >/dev/null 2>&1; then
            low=${middle}
        else
            high=${middle}
        fi
    done
    printf '%s' "${low}"
}

source_key_algorithm() {
    local cert="$1"
    local details bits curve
    details="$(openssl x509 -in "${cert}" -noout -text 2>/dev/null)" \
        || die 4 "could not read the source leaf public-key profile"
    if [[ "${details}" == *'Public Key Algorithm: rsaEncryption'* ]]; then
        bits="$(sed -n 's/.*Public-Key: (\([0-9][0-9]*\) bit).*/\1/p' <<<"${details}" | head -n 1)"
        [[ "${bits}" =~ ^[0-9]+$ && 10#${bits} -ge 2048 && 10#${bits} -le 16384 ]] \
            || die 4 "source RSA key size is unsupported; use --key-algorithm with a supported profile"
        printf 'rsa:%s' "${bits}"
    elif [[ "${details}" == *'Public Key Algorithm: id-ecPublicKey'* ]]; then
        curve="$(sed -n 's/.*\(NIST CURVE\|ASN1 OID\): //p' <<<"${details}" | head -n 1)"
        case "${curve}" in
            P-256|prime256v1) printf 'ec:p256' ;;
            P-384|secp384r1) printf 'ec:p384' ;;
            P-521|secp521r1) printf 'ec:p521' ;;
            *) die 4 "source EC curve is unsupported; use --key-algorithm with a supported profile" ;;
        esac
    elif [[ "${details}" == *'Public Key Algorithm: ED25519'* ]]; then
        printf 'ed25519'
    else
        die 4 "source public-key algorithm is unsupported; use --key-algorithm with a supported profile"
    fi
}

validate_key_algorithm() {
    local algorithm="$1"
    local bits
    case "${algorithm}" in
        rsa:*)
            bits="${algorithm#rsa:}"
            [[ "${bits}" =~ ^[0-9]+$ && 10#${bits} -ge 2048 && 10#${bits} -le 16384 ]] \
                || die 1 "--key-algorithm RSA size must be between 2048 and 16384 bits"
            ;;
        ec:p256|ec:p384|ec:p521|ed25519)
            ;;
        *)
            die 1 "--key-algorithm must be rsa:<bits>, ec:p256, ec:p384, ec:p521, or ed25519"
            ;;
    esac
}

generate_leaf_key() {
    local algorithm="$1"
    local destination="$2"
    local curve=""

    case "${algorithm}" in
        rsa:*)
            openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${algorithm#rsa:}" -out "${destination}" >/dev/null 2>&1
            ;;
        ec:p256) curve='P-256' ;;
        ec:p384) curve='P-384' ;;
        ec:p521) curve='P-521' ;;
        ed25519)
            openssl genpkey -algorithm ED25519 -out "${destination}" >/dev/null 2>&1
            return
            ;;
    esac
    if [[ -n "${curve}" ]]; then
        openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" -pkeyopt ec_param_enc:named_curve \
            -out "${destination}" >/dev/null 2>&1
    fi
}

public_key_digest() {
    local kind="$1"
    local source="$2"
    if [[ "${kind}" == "certificate" ]]; then
        openssl x509 -in "${source}" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256
    else
        openssl pkey -in "${source}" -pubout -outform DER 2>/dev/null | openssl dgst -sha256
    fi
}

source_key_usage() {
    local cert="$1"
    local extension values item result=""
    local saved_ifs="${IFS}"
    local -a items=()

    extension="$(openssl x509 -in "${cert}" -noout -ext keyUsage 2>/dev/null || true)"
    [[ "${extension}" == *$'\n'* ]] || return 0
    values="${extension#*$'\n'}"
    values="${values#${values%%[![:space:]]*}}"
    IFS=',' read -r -a items <<<"${values}"
    IFS="${saved_ifs}"
    for item in "${items[@]}"; do
        item="${item#${item%%[![:space:]]*}}"
        case "${item}" in
            'Digital Signature') item='digitalSignature' ;;
            'Non Repudiation') item='nonRepudiation' ;;
            'Key Encipherment') item='keyEncipherment' ;;
            'Data Encipherment') item='dataEncipherment' ;;
            'Key Agreement') item='keyAgreement' ;;
            'Certificate Sign'|'CRL Sign') die 4 "source leaf key usage is not valid for reissuance" ;;
            *) die 4 "source leaf key usage is unsupported: ${item}" ;;
        esac
        [[ -z "${result}" ]] || result+=','
        result+="${item}"
    done
    printf '%s' "${result}"
}

source_extended_key_usage() {
    local cert="$1"
    local extension values item result=""
    local saved_ifs="${IFS}"
    local -a items=()

    extension="$(openssl x509 -in "${cert}" -noout -ext extendedKeyUsage 2>/dev/null || true)"
    [[ "${extension}" == *$'\n'* ]] || return 0
    values="${extension#*$'\n'}"
    values="${values#${values%%[![:space:]]*}}"
    IFS=',' read -r -a items <<<"${values}"
    IFS="${saved_ifs}"
    for item in "${items[@]}"; do
        item="${item#${item%%[![:space:]]*}}"
        case "${item}" in
            'TLS Web Server Authentication') item='serverAuth' ;;
            'TLS Web Client Authentication') item='clientAuth' ;;
            'Code Signing') item='codeSigning' ;;
            'E-mail Protection') item='emailProtection' ;;
            'Time Stamping') item='timeStamping' ;;
            'OCSP Signing') item='OCSPSigning' ;;
            *) die 4 "source leaf extended key usage is unsupported: ${item}" ;;
        esac
        [[ -z "${result}" ]] || result+=','
        result+="${item}"
    done
    printf '%s' "${result}"
}

write_leaf_extension_config() {
    local destination="$1"
    local source_leaf="$2"
    local key_usage="$3"
    local extended_key_usage="$4"
    shift 4
    local san result=""
    local -a dns_sans=("$@")
    local source_san

    certificate_is_ca "${source_leaf}" && die 4 "source leaf must not be a CA certificate"
    source_san="$(certificate_sans "${source_leaf}")"
    [[ "${source_san}" != *'IP Address:'* && "${source_san}" != *'email:'* && "${source_san}" != *'URI:'* && "${source_san}" != *'othername:'* ]] \
        || die 4 "source leaf contains non-DNS SAN values that this clone profile cannot preserve"
    for san in "${dns_sans[@]}"; do
        validate_dns_name "${san}"
        [[ -z "${result}" ]] || result+=','
        result+="DNS:${san}"
    done

    {
        printf '[v3_leaf]\n'
        printf 'basicConstraints=critical,CA:FALSE\n'
        printf 'subjectKeyIdentifier=hash\n'
        printf 'authorityKeyIdentifier=keyid,issuer\n'
        [[ -z "${key_usage}" ]] || printf 'keyUsage=critical,%s\n' "${key_usage}"
        [[ -z "${extended_key_usage}" ]] || printf 'extendedKeyUsage=%s\n' "${extended_key_usage}"
        [[ -z "${result}" ]] || printf 'subjectAltName=%s\n' "${result}"
    } >"${destination}"
}

write_self_signed_extension_config() {
    local destination="$1"
    local source_leaf="$2"
    local key_usage="$3"
    local extended_key_usage="$4"
    shift 4
    local san result=""
    local -a dns_sans=("$@")
    local source_san basic_constraints

    source_san="$(certificate_sans "${source_leaf}")"
    [[ "${source_san}" != *'IP Address:'* && "${source_san}" != *'email:'* && "${source_san}" != *'URI:'* && "${source_san}" != *'othername:'* ]] \
        || die 4 "source certificate contains non-DNS SAN values that this clone profile cannot preserve"
    for san in "${dns_sans[@]}"; do
        validate_dns_name "${san}"
        [[ -z "${result}" ]] || result+=','
        result+="DNS:${san}"
    done
    if certificate_is_ca "${source_leaf}"; then
        basic_constraints='critical,CA:TRUE'
        [[ -n "${key_usage}" ]] || key_usage='keyCertSign,cRLSign'
    else
        basic_constraints='critical,CA:FALSE'
    fi
    {
        printf '[req]\n'
        printf 'distinguished_name=req_distinguished_name\n'
        printf 'prompt=no\n'
        printf '[req_distinguished_name]\n'
        printf '[v3_self_signed]\n'
        printf 'basicConstraints=%s\n' "${basic_constraints}"
        printf 'subjectKeyIdentifier=hash\n'
        printf 'authorityKeyIdentifier=keyid,issuer\n'
        [[ -z "${key_usage}" ]] || printf 'keyUsage=critical,%s\n' "${key_usage}"
        [[ -z "${extended_key_usage}" ]] || printf 'extendedKeyUsage=%s\n' "${extended_key_usage}"
        [[ -z "${result}" ]] || printf 'subjectAltName=%s\n' "${result}"
    } >"${destination}"
}

write_clone_manifest() {
    local destination="$1"
    local profile_hash="$2"
    local key_algorithm="$3"
    local source_leaf="$4"
    local issued_leaf="$5"
    local operation="$6"
    local issuer_subject="$7"
    local source_fingerprint issued_fingerprint

    source_fingerprint="$(certificate_sha256_fingerprint "${source_leaf}")"
    issued_fingerprint="$(certificate_sha256_fingerprint "${issued_leaf}")"
    {
        printf '{\n'
        printf '  "operation": "%s",\n' "${operation}"
        printf '  "tool_version": "%s",\n' "${TOOL_VERSION}"
        printf '  "clone_profile_sha256": "%s",\n' "${profile_hash}"
        printf '  "source_leaf_sha256": "%s",\n' "${source_fingerprint}"
        printf '  "issued_leaf_sha256": "%s",\n' "${issued_fingerprint}"
        printf '  "issuer_subject": "%s",\n' "$(json_escape "${issuer_subject}")"
        printf '  "key_algorithm": "%s"\n' "${key_algorithm}"
        printf '}\n'
    } >"${destination}"
}

execute_clone() {
    local profile=""
    local chain=""
    local issuer_cert=""
    local issuer_key=""
    local issuer_chain=""
    local supplied_leaf_key=""
    local output_dir=""
    local key_algorithm=""
    local issuer_mode="original"
    local payload subject subject_cn validity_days source_days issuer_days issue_days
    local source_leaf source_issuer issuer_subject index
    local key_usage extended_key_usage serial profile_hash actual_hash openssl_subject operation
    local leaf_key leaf_csr leaf_cert extension_config verification_chain
    local -a final_sans=()

    while (($# > 0)); do
        case "$1" in
            --profile)
                (($# >= 2)) || die 1 "--profile requires a file path"
                profile="$2"
                shift 2
                ;;
            --chain)
                (($# >= 2)) || die 1 "--chain requires a file path"
                chain="$2"
                shift 2
                ;;
            --issuer-cert)
                (($# >= 2)) || die 1 "--issuer-cert requires a PEM certificate"
                issuer_cert="$2"
                shift 2
                ;;
            --issuer-key)
                (($# >= 2)) || die 1 "--issuer-key requires a PEM private key"
                issuer_key="$2"
                shift 2
                ;;
            --issuer-chain)
                (($# >= 2)) || die 1 "--issuer-chain requires a PEM bundle"
                issuer_chain="$2"
                shift 2
                ;;
            --leaf-key)
                (($# >= 2)) || die 1 "--leaf-key requires a PEM private key"
                supplied_leaf_key="$2"
                shift 2
                ;;
            --key-algorithm)
                (($# >= 2)) || die 1 "--key-algorithm requires a value"
                key_algorithm="$2"
                shift 2
                ;;
            --issuer-mode)
                (($# >= 2)) || die 1 "--issuer-mode requires a value"
                issuer_mode="$2"
                shift 2
                ;;
            --out-dir)
                (($# >= 2)) || die 1 "--out-dir requires a directory"
                output_dir="$2"
                shift 2
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown internal clone option: $1"
                ;;
        esac
    done

    [[ -n "${profile}" && -n "${chain}" && -n "${issuer_cert}" && -n "${issuer_key}" && -n "${output_dir}" ]] \
        || die 1 "internal clone requires --profile, --chain, --issuer-cert, --issuer-key, and --out-dir"
    [[ -f "${issuer_cert}" && ! -L "${issuer_cert}" ]] || die 1 "--issuer-cert must be a regular file"
    [[ -f "${issuer_key}" && ! -L "${issuer_key}" ]] || die 1 "--issuer-key must be a regular file"
    [[ -z "${supplied_leaf_key}" || ( -f "${supplied_leaf_key}" && ! -L "${supplied_leaf_key}" ) ]] \
        || die 1 "--leaf-key must be a regular file"
    [[ -z "${issuer_chain}" || ( -f "${issuer_chain}" && ! -L "${issuer_chain}" ) ]] \
        || die 1 "--issuer-chain must be a regular file"
    [[ "${issuer_mode}" == 'original' || "${issuer_mode}" == 'generated' ]] \
        || die 1 "internal issuer mode is invalid"
    require_openssl
    validate_output_dir "${output_dir}"
    openssl x509 -in "${issuer_cert}" -noout >/dev/null 2>&1 || die 4 "--issuer-cert is not a readable PEM certificate"
    openssl pkey -in "${issuer_key}" -noout >/dev/null 2>&1 || die 4 "--issuer-key is not a readable private key"
    certificate_is_ca "${issuer_cert}" || die 4 "--issuer-cert is not a CA certificate"
    certificate_has_ca_signing "${issuer_cert}" || die 4 "--issuer-cert lacks Certificate Sign key usage"
    [[ "$(public_key_digest certificate "${issuer_cert}")" == "$(public_key_digest key "${issuer_key}")" ]] \
        || die 4 "--issuer-cert and --issuer-key do not match"

    APPLY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert-issue.XXXXXX")" \
        || die 1 "could not create a clone directory"
    payload="${APPLY_DIR}/clone-profile.json"
    verify_clone_profile_integrity "${profile}" "${payload}"
    profile_hash="$(awk -F'"' '/^  "profile_sha256": / { print $4; exit }' "${profile}")"

    cmd_validate --chain "${chain}" >/dev/null
    split_pem_bundle "${chain}"
    verify_clone_profile_source_chain "${payload}"
    source_leaf="${CERT_FILES[0]}"
    source_issuer="$(certificate_name "${source_leaf}" issuer)"
    issuer_subject="$(certificate_name "${issuer_cert}" subject)"
    if [[ "${issuer_mode}" == 'original' ]]; then
        [[ "${source_issuer}" == "${issuer_subject}" ]] \
            || die 4 "--issuer-cert must be the original direct issuer of the source leaf"
        openssl verify -partial_chain -CAfile "${issuer_cert}" "${source_leaf}" >/dev/null 2>&1 \
            || die 4 "--issuer-cert does not cryptographically issue the source leaf"
    fi

    subject="$(clone_profile_leaf_subject "${payload}")"
    [[ -n "${subject}" && "${subject}" != *'\\'* && "${subject}" != *'\"'* ]] \
        || die 4 "clone profile Subject contains unsupported escaped characters"
    subject_cn="$(subject_common_name "${subject}")" \
        || die 4 "clone profile Subject must include CN=<name> in RFC4514 form"
    validate_dns_name "${subject_cn}"
    openssl_subject="$(rfc2253_to_openssl_subject "${subject}")" \
        || die 4 "clone profile Subject cannot be represented safely for OpenSSL issuance"
    while IFS= read -r source_fingerprint; do
        [[ -z "${source_fingerprint}" ]] || final_sans+=("${source_fingerprint}")
    done < <(clone_profile_dns_sans "${payload}")
    validity_days="$(clone_profile_validity_days "${payload}")"
    source_days="$(remaining_validity_days "${source_leaf}")"
    issuer_days="$(remaining_validity_days "${issuer_cert}")"
    if [[ "${validity_days}" == "null" ]]; then
        issue_days=${source_days}
    else
        issue_days=${validity_days}
    fi
    ((issue_days <= issuer_days)) || issue_days=${issuer_days}
    ((issue_days >= 1)) || die 4 "source or issuing CA certificate expires in less than one day"

    if [[ -n "${supplied_leaf_key}" ]]; then
        openssl pkey -in "${supplied_leaf_key}" -noout >/dev/null 2>&1 \
            || die 4 "--leaf-key is not a readable private key"
        [[ "$(public_key_digest certificate "${source_leaf}")" == "$(public_key_digest key "${supplied_leaf_key}")" ]] \
            || die 4 "--leaf-key does not match the source leaf public key"
        key_algorithm='source-key-reused'
    elif [[ -z "${key_algorithm}" ]]; then
        key_algorithm="$(source_key_algorithm "${source_leaf}")"
    else
        validate_key_algorithm "${key_algorithm}"
    fi
    key_usage="$(source_key_usage "${source_leaf}")"
    extended_key_usage="$(source_extended_key_usage "${source_leaf}")"
    leaf_key="${APPLY_DIR}/leaf.key.pem"
    leaf_csr="${APPLY_DIR}/leaf.csr.pem"
    leaf_cert="${APPLY_DIR}/leaf.cert.pem"
    extension_config="${APPLY_DIR}/leaf-ext.cnf"
    if [[ -n "${supplied_leaf_key}" ]]; then
        cp -- "${supplied_leaf_key}" "${leaf_key}" || die 4 "could not stage --leaf-key"
    else
        generate_leaf_key "${key_algorithm}" "${leaf_key}" \
            || die 4 "could not generate a new ${key_algorithm} leaf private key"
    fi
    write_leaf_extension_config "${extension_config}" "${source_leaf}" "${key_usage}" "${extended_key_usage}" "${final_sans[@]}"
    openssl req -new -key "${leaf_key}" -subj "${openssl_subject}" -out "${leaf_csr}" >/dev/null 2>&1 \
        || die 4 "could not create the leaf certificate request"
    serial="$(openssl rand -hex 16)" || die 4 "could not generate a certificate serial number"
    openssl x509 -req -in "${leaf_csr}" -CA "${issuer_cert}" -CAkey "${issuer_key}" \
        -set_serial "0x${serial}" -days "${issue_days}" -sha256 \
        -extfile "${extension_config}" -extensions v3_leaf -out "${leaf_cert}" >/dev/null 2>&1 \
        || die 4 "could not issue the leaf certificate"

    verification_chain="${APPLY_DIR}/verification-chain.pem"
    append_file "${issuer_cert}" >"${verification_chain}"
    if [[ -n "${issuer_chain}" ]]; then
        append_file "${issuer_chain}" >>"${verification_chain}"
    fi
    openssl verify -CAfile "${verification_chain}" "${leaf_cert}" >/dev/null 2>&1 \
        || die 4 "issued leaf certificate did not verify under the supplied issuer chain"
    [[ "$(certificate_name "${leaf_cert}" subject)" == "${subject}" ]] \
        || die 4 "issued leaf Subject does not match the clone profile"

    mkdir -p -- "${output_dir}" || die 1 "could not create --out-dir: ${output_dir}"
    cp -- "${leaf_key}" "${output_dir}/leaf.key.pem" || die 4 "could not save issued leaf private key"
    cp -- "${leaf_cert}" "${output_dir}/leaf.cert.pem" || die 4 "could not save issued leaf certificate"
    { append_file "${leaf_cert}"; append_file "${verification_chain}"; } >"${output_dir}/issued-chain.pem" \
        || die 4 "could not save issued certificate chain"
    if [[ "${issuer_mode}" == 'original' ]]; then
        operation='original-issuer-reissue'
    else
        operation='generated-issuer-reissue'
    fi
    write_clone_manifest "${output_dir}/manifest.json" "${profile_hash}" "${key_algorithm}" "${source_leaf}" "${leaf_cert}" \
        "${operation}" "${issuer_subject}" \
        || die 4 "could not save issuance manifest"
    if [[ "${issuer_mode}" == 'original' ]]; then
        printf 'Reissued a leaf certificate under the supplied original issuer in %s\n' "${output_dir}"
    else
        printf 'Reissued a leaf certificate under an automatically generated issuer in %s\n' "${output_dir}"
    fi
}

execute_self_signed_clone() {
    local profile="$1"
    local chain="$2"
    local supplied_leaf_key="$3"
    local requested_key_algorithm="$4"
    local output_dir="$5"
    local payload profile_hash source_leaf subject subject_cn openssl_subject
    local validity_days source_days issue_days key_algorithm key_usage extended_key_usage
    local leaf_key leaf_cert extension_config source_fingerprint issued_fingerprint
    local san
    local -a final_sans=()

    [[ -z "${supplied_leaf_key}" || ( -f "${supplied_leaf_key}" && ! -L "${supplied_leaf_key}" ) ]] \
        || die 1 "--leaf-key must be a regular file"
    require_openssl
    validate_output_dir "${output_dir}"
    APPLY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert-self-signed.XXXXXX")" \
        || die 1 "could not create a self-signed clone directory"
    payload="${APPLY_DIR}/clone-profile.json"
    verify_clone_profile_integrity "${profile}" "${payload}"
    profile_hash="$(awk -F'"' '/^  "profile_sha256": / { print $4; exit }' "${profile}")"
    cmd_validate --chain "${chain}" >/dev/null
    split_pem_bundle "${chain}"
    verify_clone_profile_source_chain "${payload}"
    source_leaf="${CERT_FILES[0]}"

    subject="$(clone_profile_leaf_subject "${payload}")"
    [[ -n "${subject}" && "${subject}" != *'\\'* && "${subject}" != *'\"'* ]] \
        || die 4 "clone profile Subject contains unsupported escaped characters"
    subject_cn="$(subject_common_name "${subject}")" \
        || die 4 "clone profile Subject must include CN=<name> in RFC4514 form"
    validate_dns_name "${subject_cn}"
    openssl_subject="$(rfc2253_to_openssl_subject "${subject}")" \
        || die 4 "clone profile Subject cannot be represented safely for OpenSSL issuance"
    while IFS= read -r san; do
        [[ -z "${san}" ]] || final_sans+=("${san}")
    done < <(clone_profile_dns_sans "${payload}")
    validity_days="$(clone_profile_validity_days "${payload}")"
    source_days="$(remaining_validity_days "${source_leaf}")"
    if [[ "${validity_days}" == 'null' ]]; then
        issue_days="${source_days}"
    else
        issue_days="${validity_days}"
    fi
    ((issue_days <= source_days)) || issue_days=${source_days}
    ((issue_days >= 1)) || die 4 "source certificate expires in less than one day"

    if [[ -n "${supplied_leaf_key}" ]]; then
        openssl pkey -in "${supplied_leaf_key}" -noout >/dev/null 2>&1 \
            || die 4 "--leaf-key is not a readable private key"
        [[ "$(public_key_digest certificate "${source_leaf}")" == "$(public_key_digest key "${supplied_leaf_key}")" ]] \
            || die 4 "--leaf-key does not match the source leaf public key"
        key_algorithm='source-key-reused'
    elif [[ -z "${requested_key_algorithm}" ]]; then
        key_algorithm="$(source_key_algorithm "${source_leaf}")"
    else
        validate_key_algorithm "${requested_key_algorithm}"
        key_algorithm="${requested_key_algorithm}"
    fi
    if certificate_is_ca "${source_leaf}"; then
        key_usage='keyCertSign,cRLSign'
        extended_key_usage=''
    else
        key_usage="$(source_key_usage "${source_leaf}")"
        extended_key_usage="$(source_extended_key_usage "${source_leaf}")"
    fi
    leaf_key="${APPLY_DIR}/leaf.key.pem"
    leaf_cert="${APPLY_DIR}/leaf.cert.pem"
    extension_config="${APPLY_DIR}/self-signed-ext.cnf"
    if [[ -n "${supplied_leaf_key}" ]]; then
        cp -- "${supplied_leaf_key}" "${leaf_key}" || die 4 "could not stage --leaf-key"
    else
        generate_leaf_key "${key_algorithm}" "${leaf_key}" \
            || die 4 "could not generate a new ${key_algorithm} leaf private key"
    fi
    write_self_signed_extension_config "${extension_config}" "${source_leaf}" "${key_usage}" "${extended_key_usage}" "${final_sans[@]}"
    openssl req -new -x509 -key "${leaf_key}" -subj "${openssl_subject}" -days "${issue_days}" -sha256 \
        -config "${extension_config}" -extensions v3_self_signed -out "${leaf_cert}" >/dev/null 2>&1 \
        || die 4 "could not issue the self-signed clone"
    [[ "$(certificate_name "${leaf_cert}" subject)" == "$(certificate_name "${leaf_cert}" issuer)" ]] \
        || die 4 "issued certificate is not self-signed"
    [[ "$(certificate_name "${leaf_cert}" subject)" == "${subject}" ]] \
        || die 4 "issued self-signed Subject does not match the clone profile"

    mkdir -p -- "${output_dir}" || die 1 "could not create --out-dir: ${output_dir}"
    cp -- "${leaf_key}" "${output_dir}/leaf.key.pem" || die 4 "could not save self-signed leaf private key"
    cp -- "${leaf_cert}" "${output_dir}/leaf.cert.pem" || die 4 "could not save self-signed leaf certificate"
    append_file "${leaf_cert}" >"${output_dir}/issued-chain.pem" || die 4 "could not save self-signed certificate chain"
    write_clone_manifest "${output_dir}/manifest.json" "${profile_hash}" "${key_algorithm}" "${source_leaf}" "${leaf_cert}" \
        'self-signed-clone' "${subject}" || die 4 "could not save self-signed manifest"
    printf 'Created a self-signed certificate clone in %s\n' "${output_dir}"
}

cmd_clone() {
    local chain=""
    local issuer_cert=""
    local issuer_key=""
    local issuer_chain=""
    local fake_issuer_subject=""
    local leaf_key=""
    local output_dir=""
    local key_algorithm=""
    local dry_run=false
    local force_self_signed=false
    local original_issuer_only=false
    local source_leaf source_issuer source_days clone_mode
    local -a change_options=()
    local -a issue_options=()

    while (($# > 0)); do
        case "$1" in
            --chain|--issuer-cert|--issuer-key|--issuer-chain|--fake-issuer-subject|--leaf-key|--out-dir|--key-algorithm)
                (($# >= 2)) || die 1 "$1 requires a value"
                case "$1" in
                    --chain) chain="$2" ;;
                    --issuer-cert) issuer_cert="$2" ;;
                    --issuer-key) issuer_key="$2" ;;
                    --issuer-chain) issuer_chain="$2" ;;
                    --fake-issuer-subject) fake_issuer_subject="$2" ;;
                    --leaf-key) leaf_key="$2" ;;
                    --out-dir) output_dir="$2" ;;
                    --key-algorithm) key_algorithm="$2" ;;
                esac
                shift 2
                ;;
            --set-leaf-subject|--set-leaf-san|--set-validity-days|--set-field)
                (($# >= 2)) || die 1 "$1 requires a value"
                change_options+=("$1" "$2")
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --self-signed)
                force_self_signed=true
                shift
                ;;
            --original-issuer-only)
                original_issuer_only=true
                shift
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                die 1 "unknown clone option: $1"
                ;;
        esac
    done

    [[ -n "${chain}" && -n "${output_dir}" ]] || die 1 "clone requires --chain and --out-dir"
    [[ -z "${issuer_cert}" || -n "${issuer_key}" ]] || die 1 "--issuer-cert requires --issuer-key"
    [[ -z "${issuer_key}" || -n "${issuer_cert}" ]] || die 1 "--issuer-key requires --issuer-cert"
    [[ -z "${issuer_chain}" || -n "${issuer_cert}" ]] || die 1 "--issuer-chain requires --issuer-cert and --issuer-key"
    [[ -z "${fake_issuer_subject}" || -z "${issuer_cert}" ]] \
        || die 1 "--fake-issuer-subject cannot be combined with an original issuer"
    [[ "${force_self_signed}" == false || -z "${issuer_cert}" ]] \
        || die 1 "--self-signed cannot be combined with an original issuer"
    [[ "${force_self_signed}" == false || -z "${fake_issuer_subject}" ]] \
        || die 1 "--self-signed cannot be combined with --fake-issuer-subject"

    require_openssl
    cmd_validate --chain "${chain}" >/dev/null
    split_pem_bundle "${chain}"
    source_leaf="${CERT_FILES[0]}"
    source_issuer="$(certificate_name "${source_leaf}" issuer)"
    source_days="$(remaining_validity_days "${source_leaf}")"
    if [[ "${force_self_signed}" == true ]] || source_is_self_issued "${source_leaf}"; then
        clone_mode='self-signed'
    elif [[ -n "${issuer_cert}" ]]; then
        clone_mode='original-issuer'
    elif [[ "${original_issuer_only}" == true ]]; then
        die 1 "--original-issuer-only requires --issuer-cert and --issuer-key for a CA-issued source"
    else
        clone_mode='generated-issuer'
        if [[ -z "${fake_issuer_subject}" ]]; then
            fake_issuer_subject="$(derive_fake_issuer_subject "${source_issuer}")" \
                || die 4 "could not derive a fake issuer Subject from the source issuer; use --fake-issuer-subject"
        fi
        rfc2253_to_openssl_subject "${fake_issuer_subject}" >/dev/null \
            || die 4 "fake issuer Subject cannot be represented safely for OpenSSL issuance"
    fi

    CLONE_PROFILE_FILE="$(mktemp "${TMPDIR:-/tmp}/clone-cert-clone.XXXXXX.json")" \
        || die 1 "could not create a temporary clone profile"
    rm -f -- "${CLONE_PROFILE_FILE}"
    prepare_clone_profile --chain "${chain}" --profile "${CLONE_PROFILE_FILE}" "${change_options[@]}" >/dev/null
    if [[ "${dry_run}" == true ]]; then
        printf 'Clone review completed: %s mode; no certificate, key, or output artifact was created.\n' "${clone_mode}"
        if [[ "${clone_mode}" == 'generated-issuer' ]]; then
            printf 'Generated issuer Subject: %s\n' "${fake_issuer_subject}"
        fi
        return 0
    fi
    if [[ "${clone_mode}" == 'self-signed' ]]; then
        execute_self_signed_clone "${CLONE_PROFILE_FILE}" "${chain}" "${leaf_key}" "${key_algorithm}" "${output_dir}"
        return 0
    fi
    if [[ "${clone_mode}" == 'generated-issuer' ]]; then
        ((source_days >= 1)) || die 4 "source certificate expires in less than one day"
        generate_automatic_issuer "${source_issuer}" "${fake_issuer_subject}" "$((source_days + 1))"
        issuer_cert="${AUTO_ISSUER_CERT}"
        issuer_key="${AUTO_ISSUER_KEY}"
    fi
    issue_options=(--profile "${CLONE_PROFILE_FILE}" --chain "${chain}" --issuer-cert "${issuer_cert}" --issuer-key "${issuer_key}" --out-dir "${output_dir}")
    [[ -z "${issuer_chain}" ]] || issue_options+=(--issuer-chain "${issuer_chain}")
    [[ -z "${leaf_key}" ]] || issue_options+=(--leaf-key "${leaf_key}")
    [[ -z "${key_algorithm}" ]] || issue_options+=(--key-algorithm "${key_algorithm}")
    [[ "${clone_mode}" == 'original-issuer' ]] || issue_options+=(--issuer-mode generated)
    execute_clone "${issue_options[@]}"
    if [[ "${clone_mode}" == 'generated-issuer' ]]; then
        cp -- "${AUTO_ISSUER_CERT}" "${output_dir}/generated-issuer.cert.pem" \
            || die 4 "could not save the generated issuer certificate"
        cp -- "${AUTO_ISSUER_KEY}" "${output_dir}/generated-issuer.key.pem" \
            || die 4 "could not save the generated issuer private key"
        printf 'Warning: the generated issuer is not trusted by clients unless it is explicitly installed.\n'
    fi
}

selftest_pass() {
    printf 'PASS %s\n' "$1"
}

selftest_fail() {
    printf 'FAIL %s: %s\n' "$1" "$2" >&2
    return 1
}

append_file() {
    local source="$1"
    local line
    while IFS= read -r line || [[ -n "${line}" ]]; do
        printf '%s\n' "${line}"
    done <"${source}"
}

cmd_self_test() {
    local script_path="${BASH_SOURCE[0]}"
    local root_key root_cert intermediate_key intermediate_csr intermediate_cert
    local leaf_key leaf_csr leaf_cert self_signed_key self_signed_cert self_signed_chain
    local complete missing_root wrong_order output capture_output clone_output generated_output self_signed_output rejected_output nonempty_output failure_output dry_run_output
    local server_port="" attempt

    require_openssl
    SELFTEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clone-cert-selftest.XXXXXX")" \
        || die 1 "could not create a self-test directory"
    root_key="${SELFTEST_DIR}/root.key.pem"
    root_cert="${SELFTEST_DIR}/root.cert.pem"
    intermediate_key="${SELFTEST_DIR}/intermediate.key.pem"
    intermediate_csr="${SELFTEST_DIR}/intermediate.csr.pem"
    intermediate_cert="${SELFTEST_DIR}/intermediate.cert.pem"
    leaf_key="${SELFTEST_DIR}/leaf.key.pem"
    leaf_csr="${SELFTEST_DIR}/leaf.csr.pem"
    leaf_cert="${SELFTEST_DIR}/leaf.cert.pem"
    self_signed_key="${SELFTEST_DIR}/self-signed.key.pem"
    self_signed_cert="${SELFTEST_DIR}/self-signed.cert.pem"
    self_signed_chain="${SELFTEST_DIR}/self-signed-chain.pem"
    complete="${SELFTEST_DIR}/complete-chain.pem"
    missing_root="${SELFTEST_DIR}/missing-root.pem"
    wrong_order="${SELFTEST_DIR}/wrong-order.pem"
    output="${SELFTEST_DIR}/output.txt"
    capture_output="${SELFTEST_DIR}/capture"
    clone_output="${SELFTEST_DIR}/clone-output"
    generated_output="${SELFTEST_DIR}/generated-output"
    self_signed_output="${SELFTEST_DIR}/self-signed-output"
    rejected_output="${SELFTEST_DIR}/rejected-output"
    nonempty_output="${SELFTEST_DIR}/nonempty-output"
    failure_output="${SELFTEST_DIR}/failure-output"
    dry_run_output="${SELFTEST_DIR}/dry-run-output"

    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
        -subj '/CN=clone-cert self-test root' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "${root_key}" -out "${root_cert}" >/dev/null 2>&1 \
        || selftest_fail T-014 "could not create root fixture"

    openssl req -newkey rsa:2048 -nodes -sha256 \
        -subj '/CN=clone-cert self-test intermediate' \
        -keyout "${intermediate_key}" -out "${intermediate_csr}" >/dev/null 2>&1 \
        || selftest_fail T-014 "could not create intermediate CSR"
    openssl x509 -req -in "${intermediate_csr}" -CA "${root_cert}" -CAkey "${root_key}" \
        -CAcreateserial -days 1 -sha256 -out "${intermediate_cert}" \
        -extfile <(printf '%s\n' '[v3_ca]' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign') \
        -extensions v3_ca >/dev/null 2>&1 \
        || selftest_fail T-014 "could not issue intermediate fixture"

    openssl req -newkey rsa:2048 -nodes -sha256 \
        -subj '/CN=service.lab.test' \
        -keyout "${leaf_key}" -out "${leaf_csr}" >/dev/null 2>&1 \
        || selftest_fail T-014 "could not create leaf CSR"
    openssl x509 -req -in "${leaf_csr}" -CA "${intermediate_cert}" -CAkey "${intermediate_key}" \
        -CAcreateserial -days 1 -sha256 -out "${leaf_cert}" \
        -extfile <(printf '%s\n' '[v3_leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:service.lab.test') \
        -extensions v3_leaf >/dev/null 2>&1 \
        || selftest_fail T-014 "could not issue leaf fixture"

    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
        -subj '/CN=self-signed.example.test,O=clone-cert self-test,C=ES' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "${self_signed_key}" -out "${self_signed_cert}" >/dev/null 2>&1 \
        || selftest_fail T-014 "could not create self-signed fixture"

    { append_file "${leaf_cert}"; append_file "${intermediate_cert}"; append_file "${root_cert}"; } >"${complete}"
    { append_file "${leaf_cert}"; append_file "${intermediate_cert}"; } >"${missing_root}"
    { append_file "${intermediate_cert}"; append_file "${leaf_cert}"; append_file "${root_cert}"; } >"${wrong_order}"
    append_file "${self_signed_cert}" >"${self_signed_chain}"

    bash "${script_path}" inspect --chain "${complete}" --format json >"${output}" \
        || selftest_fail T-001 "inspect rejected a complete chain"
    [[ "$(<"${output}")" == *'"position": 0'* && "$(<"${output}")" == *'"position": 2'* ]] \
        || selftest_fail T-001 "inspect JSON does not contain three certificates"
    selftest_pass T-001

    bash "${script_path}" validate --chain "${complete}" >"${output}" \
        || selftest_fail T-001 "validate rejected a complete chain"
    [[ "$(<"${output}")" == *'complete self-signed root'* ]] \
        || selftest_fail T-001 "complete chain result was not reported"
    selftest_pass T-001-chain-validation

    bash "${script_path}" validate --chain "${missing_root}" >"${output}" \
        || selftest_fail T-002 "validate rejected a chain without its root"
    [[ "$(<"${output}")" == *'no self-signed root was presented'* ]] \
        || selftest_fail T-002 "missing root warning was not reported"
    selftest_pass T-002

    if bash "${script_path}" validate --chain "${wrong_order}" >"${output}" 2>&1; then
        selftest_fail T-003 "validate accepted a chain in the wrong order"
    fi
    [[ "$(<"${output}")" == *'issuer DN does not match'* ]] \
        || selftest_fail T-003 "wrong order did not produce the expected error"
    selftest_pass T-003

    for ((attempt = 0; attempt < 5; attempt++)); do
        server_port=$((20000 + RANDOM % 20000))
        openssl s_server -accept "${server_port}" -cert "${leaf_cert}" -key "${leaf_key}" \
            -cert_chain "${intermediate_cert}" -www >"${SELFTEST_DIR}/server.log" 2>&1 &
        SELFTEST_SERVER_PID=$!
        sleep 1
        if kill -0 "${SELFTEST_SERVER_PID}" 2>/dev/null; then
            break
        fi
        wait "${SELFTEST_SERVER_PID}" 2>/dev/null || true
        SELFTEST_SERVER_PID=""
        server_port=""
    done
    [[ -n "${server_port}" ]] || selftest_fail T-005 "could not start a local TLS test server"
    bash "${script_path}" "127.0.0.1:${server_port}" --sni service.lab.test \
        --timeout-seconds 5 --out-dir "${capture_output}" >"${output}" \
        || selftest_fail T-005 "positional capture rejected a local TLS chain"
    [[ $(find "${capture_output}" -type f -name '*-chain.pem' | wc -l) -eq 1 && $(find "${capture_output}" -type f -name manifest.json | wc -l) -eq 1 ]] \
        || selftest_fail T-005 "positional capture did not save the expected files"
    selftest_pass T-005

    [[ "$(transport_for_port 25)" == 'starttls-smtp' && "$(transport_for_port 4433)" == 'dtls' && "$(transport_for_port 20000)" == 'tls' ]] \
        || selftest_fail T-017 "standard transport mapping is incorrect"
    selftest_pass T-017

    kill "${SELFTEST_SERVER_PID}" 2>/dev/null || true
    wait "${SELFTEST_SERVER_PID}" 2>/dev/null || true
    SELFTEST_SERVER_PID=""

    bash "${script_path}" fields --chain "${complete}" >"${output}" \
        || selftest_fail T-006 "fields rejected a complete chain"
    [[ "$(<"${output}")" == *'Certificate 0 complete decoded fields'* && "$(<"${output}")" == *'X509v3 extensions'* ]] \
        || selftest_fail T-006 "fields did not return decoded certificate data"
    selftest_pass T-006

    bash "${script_path}" clone --chain "${complete}" --issuer-cert "${intermediate_cert}" --issuer-key "${intermediate_key}" \
        --out-dir "${dry_run_output}" --dry-run >"${output}" \
        || selftest_fail T-007 "profile-preserving clone review failed"
    [[ "$(<"${output}")" == *'Clone review completed'* && ! -e "${dry_run_output}" ]] \
        || selftest_fail T-007 "clone dry-run created output or did not report completion"
    selftest_pass T-007

    if bash "${script_path}" clone --chain "${complete}" --issuer-cert "${intermediate_cert}" --issuer-key "${intermediate_key}" \
        --out-dir "${dry_run_output}" --dry-run --set-leaf-san 'invalid_name' >"${output}" 2>&1; then
        selftest_fail T-008 "clone accepted a malformed DNS SAN"
    fi
    [[ "$(<"${output}")" == *'DNS name is invalid'* ]] \
        || selftest_fail T-008 "malformed DNS SAN did not produce the expected error"
    selftest_pass T-008

    mkdir -- "${nonempty_output}"
    printf 'sentinel\n' >"${nonempty_output}/sentinel.txt"
    if bash "${script_path}" clone --chain "${complete}" --issuer-cert "${intermediate_cert}" --issuer-key "${intermediate_key}" \
        --out-dir "${nonempty_output}" >"${output}" 2>&1; then
        selftest_fail T-011 "clone accepted a non-empty output directory"
    fi
    [[ "$(<"${nonempty_output}/sentinel.txt")" == 'sentinel' && $(find "${nonempty_output}" -mindepth 1 -maxdepth 1 | wc -l) -eq 1 ]] \
        || selftest_fail T-011 "clone modified a non-empty output directory"
    selftest_pass T-011

    if bash "${script_path}" clone --chain "${complete}" --issuer-cert "${intermediate_cert}" --issuer-key "${root_key}" \
        --out-dir "${failure_output}" >"${output}" 2>&1; then
        selftest_fail T-012 "clone accepted a mismatched issuer private key"
    fi
    [[ ! -e "${failure_output}" ]] \
        || selftest_fail T-012 "a failed clone created output artifacts"
    selftest_pass T-012

    bash "${script_path}" clone --chain "${complete}" --out-dir "${generated_output}" >"${output}" \
        || selftest_fail T-013 "automatic generated-issuer clone failed"
    [[ -s "${generated_output}/generated-issuer.key.pem" && -s "${generated_output}/generated-issuer.cert.pem" \
        && "$(<"${generated_output}/manifest.json")" == *'generated-issuer-reissue'* ]] \
        || selftest_fail T-013 "automatic generated-issuer clone did not save its issuer artifacts"
    openssl verify -partial_chain -CAfile "${generated_output}/generated-issuer.cert.pem" "${generated_output}/leaf.cert.pem" >/dev/null 2>&1 \
        || selftest_fail T-013 "automatic generated issuer did not verify the issued leaf"
    selftest_pass T-013

    bash "${script_path}" clone --chain "${self_signed_chain}" --out-dir "${self_signed_output}" >"${output}" \
        || selftest_fail T-014 "automatic self-signed clone failed"
    [[ "$(certificate_name "${self_signed_output}/leaf.cert.pem" subject)" == "$(certificate_name "${self_signed_output}/leaf.cert.pem" issuer)" \
        && "$(<"${self_signed_output}/manifest.json")" == *'self-signed-clone'* ]] \
        || selftest_fail T-014 "automatic self-signed clone is not self-signed"
    selftest_pass T-014

    bash "${script_path}" clone --chain "${complete}" --issuer-cert "${intermediate_cert}" --issuer-key "${intermediate_key}" \
        --issuer-chain "${root_cert}" --leaf-key "${leaf_key}" --set-field subject.O=Laboratory \
        --set-leaf-san override.example.test --set-validity-days 1 --out-dir "${clone_output}" >"${output}" \
        || selftest_fail T-010 "clone rejected a valid original issuer and source leaf key"
    [[ -s "${clone_output}/leaf.key.pem" && -s "${clone_output}/leaf.cert.pem" && -s "${clone_output}/issued-chain.pem" && -s "${clone_output}/manifest.json" ]] \
        || selftest_fail T-010 "clone did not save the expected artifacts"
    [[ "$(certificate_name "${clone_output}/leaf.cert.pem" subject)" == *'O=Laboratory'* ]] \
        || selftest_fail T-015 "generic Subject field override was not issued"
    selftest_pass T-015
    openssl verify -CAfile "${root_cert}" -untrusted "${intermediate_cert}" "${clone_output}/leaf.cert.pem" >/dev/null 2>&1 \
        || selftest_fail T-010 "issued leaf did not verify under the original issuer chain"
    [[ "$(public_key_digest certificate "${clone_output}/leaf.cert.pem")" == "$(public_key_digest certificate "${leaf_cert}")" ]] \
        || selftest_fail T-010 "--leaf-key did not preserve the source leaf public key"
    selftest_pass T-010

    printf 'SUMMARY 15 passed, 0 failed, 0 skipped\n'
}

main() {
    (($# > 0)) || {
        usage
        exit 1
    }

    case "$1" in
        inspect)
            shift
            cmd_inspect "$@"
            ;;
        fields)
            shift
            cmd_fields "$@"
            ;;
        validate)
            shift
            cmd_validate "$@"
            ;;
        clone)
            shift
            cmd_clone "$@"
            ;;
        --self-test)
            shift
            (($# == 0)) || die 1 "--self-test does not accept additional options"
            cmd_self_test
            ;;
        --help|-h)
            usage
            ;;
        --version)
            printf '%s %s\n' "${TOOL_NAME}" "${TOOL_VERSION}"
            ;;
        *)
            cmd_capture "$@"
            ;;
    esac
}

main "$@"
