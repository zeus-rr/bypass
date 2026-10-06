#!/usr/bin/env bash
#
#
# Ferramenta para extração de hashes de arquivos protegidos,
# identificação automática do tipo de arquivo, histórico, relatórios,
# geração de wordlists com Crunch, download de arquivos a partir de URLs
# e recriptografia com nova senha (exige senha atual conhecida).
#
# Use somente em arquivos próprios ou com autorização para auditoria.
# Não utilize para atacar sites, logins ou sistemas de terceiros.
#

set -o pipefail

VERSION="3.7"
APP_NAME="Extrator PRO"
DEFAULT_WORDLIST="/usr/share/wordlists/rockyou.txt"
BASE_DIR="${HOME}/.extrator-pro"
HISTORY_FILE="${BASE_DIR}/historico.csv"
REPORT_DIR="${BASE_DIR}/relatorios"
HASH_DIR="${BASE_DIR}/hashes"
WORDLIST_DIR="${BASE_DIR}/wordlists"
DOWNLOAD_DIR="${BASE_DIR}/downloads"
RECRYPT_DIR="${BASE_DIR}/recriptografados"
MAX_DOWNLOAD_BYTES=524288000

# ---------- Interface ----------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' BOLD='' RESET=''
fi

info()    { printf "%b\n" "${CYAN}[INFO]${RESET} $*"; }
success() { printf "%b\n" "${GREEN}[OK]${RESET} $*"; }
warn()    { printf "%b\n" "${YELLOW}[AVISO]${RESET} $*"; }
error()   { printf "%b\n" "${RED}[ERRO]${RESET} $*" >&2; }

init_dirs() {
    mkdir -p "$BASE_DIR" "$REPORT_DIR" "$HASH_DIR" "$WORDLIST_DIR" "$DOWNLOAD_DIR" "$RECRYPT_DIR" || {
        error "Não foi possível criar os diretórios de trabalho."
        exit 1
    }

    if [[ ! -f "$HISTORY_FILE" ]]; then
        printf '%s\n' 'data,hora,arquivo,tipo,ferramenta,hash_saida,status' > "$HISTORY_FILE"
    fi
}

pause_menu() {
    printf "\n"
    read -r -p "Pressione ENTER para continuar..." _
}

copy_to_clipboard() {
    local text="$1"

    if check_command wl-copy; then
        printf '%s' "$text" | wl-copy && return 0
    fi
    if check_command xclip; then
        printf '%s' "$text" | xclip -selection clipboard && return 0
    fi
    if check_command xsel; then
        printf '%s' "$text" | xsel --clipboard --input && return 0
    fi
    if check_command pbcopy; then
        printf '%s' "$text" | pbcopy && return 0
    fi
    if check_command clip.exe; then
        printf '%s' "$text" | clip.exe && return 0
    fi
    if check_command termux-clipboard-set; then
        printf '%s' "$text" | termux-clipboard-set && return 0
    fi
    return 1
}

read_hash_content() {
    local file="$1"
    if [[ -n "$file" && -f "$file" && -r "$file" ]]; then
        # Remove quebras finais para colar limpo no John / outras ferramentas.
        tr -d '\r' < "$file" | sed '/^[[:space:]]*$/d'
        return 0
    fi
    return 1
}

offer_copy_hash() {
    local file="${1:-${LAST_HASH:-}}"
    local content choice

    content="$(read_hash_content "$file")" || {
        error "Nenhum hash disponível para copiar."
        return 1
    }

    printf "\n%b\n" "${BOLD}=== HASH EXTRAÍDO ===${RESET}"
    printf "%b\n" "${CYAN}${content}${RESET}"
    printf "Arquivo: %s\n" "$file"
    printf "\n"
    printf "  %b[C]%b Copiar hash    %b[B]%b Buscar online    %b[Enter]%b Continuar\n" \
        "$GREEN$BOLD" "$RESET" "$YELLOW$BOLD" "$RESET" "$WHITE" "$RESET"
    read -r -p "Escolha: " choice

    if [[ "$choice" =~ ^[Cc]$ ]]; then
        if copy_to_clipboard "$content"; then
            success "Hash copiado para a área de transferência."
        else
            warn "Não foi possível copiar automaticamente (instale xclip, xsel ou wl-copy)."
            printf "\nSelecione e copie manualmente:\n%s\n" "$content"
        fi
    elif [[ "$choice" =~ ^[Bb]$ ]]; then
        lookup_hash_online "$content"
    fi
}

copy_last_hash_menu() {
    printf "%b\n" "${BLUE}${BOLD}=== COPIAR HASH ===${RESET}"

    if [[ -z "${LAST_HASH:-}" || ! -f "$LAST_HASH" ]]; then
        warn "Nenhum hash extraído nesta sessão."
        printf "Use a opção 1 ou 10 primeiro, ou informe um arquivo .hash\n"
        read -r -p "Caminho do arquivo de hash (Enter para voltar): " custom
        [[ -n "$custom" ]] || { pause_menu; return; }
        custom="$(resolve_existing_file "$custom")" || {
            error "Arquivo não encontrado."
            pause_menu
            return
        }
        LAST_HASH="$custom"
    else
        info "Último hash: $LAST_HASH"
    fi

    offer_copy_hash "$LAST_HASH"
    pause_menu
}

is_file_format_hash() {
    local value="$1"
    [[ "$value" == *'$pdf$'* || "$value" == *'$pkzip'* || "$value" == *'$zip2$'* \
        || "$value" == *'$rar'* || "$value" == *'$7z$'* || "$value" == *'$office$'* ]]
}

extract_simple_digest() {
    local raw="$1"
    local token

    token="$(printf '%s' "$raw" | tr -d '[:space:]')"

    # Formatos do John: $SHA256$hash  /  $SHA1$hash  /  $dynamic_61$hash
    if [[ "$token" =~ ^\$SHA256\$([0-9A-Fa-f]{64}) ]]; then
        printf 'sha256 %s\n' "${BASH_REMATCH[1],,}"
        return 0
    fi
    if [[ "$token" =~ ^\$SHA1\$([0-9A-Fa-f]{40}) ]]; then
        printf 'sha1 %s\n' "${BASH_REMATCH[1],,}"
        return 0
    fi
    if [[ "$token" =~ ^\$SHA256\$ ]]; then
        token="${token#\$SHA256\$}"
    elif [[ "$token" =~ ^\$SHA1\$ ]]; then
        token="${token#\$SHA1\$}"
    fi

    token="$(printf '%s' "$token" | tr 'A-F' 'a-f')"

    # Linha do John: usuario:hash  → pega o campo do hash
    if [[ "$token" == *:* ]]; then
        token="${token#*:}"
        token="${token%%:*}"
    fi

    if [[ "$token" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'sha256 %s\n' "$token"
        return 0
    fi
    if [[ "$token" =~ ^[0-9a-f]{40}$ ]]; then
        printf 'sha1 %s\n' "$token"
        return 0
    fi
    if [[ "$token" =~ ^[0-9a-f]{32}$ ]]; then
        printf 'md5 %s\n' "$token"
        return 0
    fi

    token="$(printf '%s' "$raw" | grep -Eo '[0-9A-Fa-f]{32,64}' | head -n 1 | tr 'A-F' 'a-f')"
    if [[ "$token" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'sha256 %s\n' "$token"
        return 0
    fi
    if [[ "$token" =~ ^[0-9a-f]{40}$ ]]; then
        printf 'sha1 %s\n' "$token"
        return 0
    fi
    if [[ "$token" =~ ^[0-9a-f]{32}$ ]]; then
        printf 'md5 %s\n' "$token"
        return 0
    fi

    return 1
}

http_get() {
    local url="$1"
    if check_command curl; then
        curl -fsSL --max-time 20 --connect-timeout 12 \
            -A "ExtratorPRO/3.6 (consulta autorizada)" \
            "$url"
        return $?
    fi
    if check_command wget; then
        wget -q -O - --timeout=20 "$url"
        return $?
    fi
    return 1
}

lookup_md5_public() {
    local digest="$1"
    local result

    result="$(http_get "https://www.nitrxgen.net/md5db/${digest}")" || return 1
    result="$(printf '%s' "$result" | tr -d '\r' | sed '/^[[:space:]]*$/d')"
    [[ -n "$result" ]] || return 1
    # Resposta deve ser texto curto (senha), não HTML de erro.
    if [[ ${#result} -gt 256 || "$result" == *'<html'* ]]; then
        return 1
    fi
    printf '%s\n' "$result"
}

lookup_sha1_public() {
    local digest="$1"
    local result

    result="$(http_get "https://sha1.gromweb.com/query/${digest}")" || return 1
    result="$(printf '%s' "$result" | tr -d '\r' | sed '/^[[:space:]]*$/d')"
    [[ -n "$result" && ${#result} -le 256 && "$result" != *'<html'* ]] || return 1
    printf '%s\n' "$result"
}

lookup_sha256_public() {
    local digest="$1"
    local result json

    # 1) gromweb (quando disponível)
    result="$(http_get "https://sha256.gromweb.com/query/${digest}" 2>/dev/null)" || true
    result="$(printf '%s' "$result" | tr -d '\r' | sed '/^[[:space:]]*$/d')"
    if [[ -n "$result" && ${#result} -le 256 && "$result" != *'<html'* && "$result" != *'{'* ]]; then
        printf '%s\n' "$result"
        return 0
    fi

    # 2) CIRCL hashlookup (hashes de arquivos conhecidos, não senhas genéricas)
    json="$(http_get "https://hashlookup.circl.lu/lookup/sha256/${digest}" 2>/dev/null)" || true
    if [[ -n "$json" && "$json" == *'"FileName"'* ]]; then
        result="$(printf '%s' "$json" | grep -o '"FileName"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed 's/.*"FileName"[[:space:]]*:[[:space:]]*"//;s/"$//')"
        if [[ -n "$result" ]]; then
            printf '[arquivo conhecido] %s\n' "$result"
            return 0
        fi
    fi

    return 1
}

john_format_for_kind() {
    case "$1" in
        md5)    printf '%s\n' "Raw-MD5" ;;
        sha1)   printf '%s\n' "Raw-SHA1" ;;
        sha256) printf '%s\n' "Raw-SHA256" ;;
        *) return 1 ;;
    esac
}

crack_digest_with_john() {
    local kind="$1"
    local digest="$2"
    local fmt john_bin hashfile confirm rc shown

    fmt="$(john_format_for_kind "$kind")" || return 1
    john_bin="$(find_john)" || {
        error "John the Ripper não foi encontrado."
        return 1
    }

    printf "\n%b\n" "${BOLD}Decifrar ${kind^^} localmente com John${RESET}"
    printf "Formato John: %s\n" "$fmt"

    if ! choose_wordlist; then
        return 1
    fi

    hashfile="$(mktemp "${TMPDIR:-/tmp}/extrator-XXXXXX.hash")" || return 1
    printf '%s\n' "$digest" > "$hashfile"

    printf "\n"
    read -r -p "Iniciar John ($fmt) com a wordlist escolhida? (s/N): " confirm
    if [[ ! "$confirm" =~ ^[SsYy]$ ]]; then
        rm -f "$hashfile"
        warn "Operação cancelada."
        return 1
    fi

    info "Executando John..."
    "$john_bin" --format="$fmt" --wordlist="$SELECTED_WORDLIST" "$hashfile"
    rc=$?

    printf "\n%b\n" "${BOLD}Resultado (--show)${RESET}"
    shown="$("$john_bin" --format="$fmt" --show "$hashfile" 2>/dev/null || true)"
    printf '%s\n' "$shown"

    LAST_HASH="$hashfile"
    if [[ "$shown" == *:* && "$shown" != *"0 password hashes cracked"* ]]; then
        LAST_PLAINTEXT="${shown#*:}"
        LAST_PLAINTEXT="${LAST_PLAINTEXT%%$'\n'*}"
        success "Possível senha: $LAST_PLAINTEXT"
        copy_to_clipboard "$LAST_PLAINTEXT" && success "Senha copiada."
        return 0
    fi

    warn "Não encontrado nesta wordlist (código $rc)."
    return 1
}

lookup_hash_online() {
    local raw="$1"
    local kind digest found confirm local_choice

    printf "\n%b\n" "${BLUE}${BOLD}=== BUSCAR HASH (MD5 / SHA1 / SHA256) ===${RESET}"
    printf "Consulta bases públicas de hashes já conhecidos.\n"
    printf "Não ataca sites, logins nem páginas de terceiros.\n"
    printf "O hash pode ser enviado a um serviço externo.\n\n"

    if [[ -z "$raw" ]]; then
        if [[ -n "${LAST_HASH:-}" && -f "$LAST_HASH" ]]; then
            raw="$(read_hash_content "$LAST_HASH")"
            info "Usando o último hash extraído."
        else
            read -r -p "Cole o hash (MD5 / SHA1 / SHA256) ou Enter para voltar: " raw
        fi
    fi

    [[ -n "$raw" ]] || { warn "Nenhum hash informado."; return 1; }

    if is_file_format_hash "$raw"; then
        warn "Este é um hash de arquivo (PDF/ZIP/RAR/7z/Office)."
        printf "Bases públicas de MD5/SHA1/SHA256 %bnão decifram%b esse formato.\n" "$BOLD" "$RESET"
        printf "Use a opção 2 (John the Ripper) com uma wordlist.\n"
        return 1
    fi

    if ! read -r kind digest < <(extract_simple_digest "$raw"); then
        error "Não foi possível identificar MD5 (32 hex), SHA1 (40 hex) ou SHA256 (64 hex)."
        warn "Hashes de PDF/ZIP extraídos pelo John não funcionam nesta consulta."
        return 1
    fi

    printf "Tipo  : %s\n" "$kind"
    printf "Digest: %s\n\n" "$digest"

    read -r -p "Consultar em base pública? (s/N): " confirm
    if [[ "$confirm" =~ ^[SsYy]$ ]]; then
        info "Consultando base pública ($kind)..."
        found=""
        case "$kind" in
            md5)    found="$(lookup_md5_public "$digest" 2>/dev/null || true)" ;;
            sha1)   found="$(lookup_sha1_public "$digest" 2>/dev/null || true)" ;;
            sha256) found="$(lookup_sha256_public "$digest" 2>/dev/null || true)" ;;
        esac

        if [[ -n "$found" ]]; then
            success "Possível resultado encontrado:"
            printf "%b%s%b\n" "$GREEN$BOLD" "$found" "$RESET"
            LAST_PLAINTEXT="$found"
            copy_to_clipboard "$found" && success "Copiado para a área de transferência."
            return 0
        fi
        warn "Não encontrado na base pública (comum em SHA256)."
    else
        warn "Consulta pública pulada."
    fi

    printf "\n"
    read -r -p "Decifrar $kind localmente com John + wordlist? (s/N): " local_choice
    if [[ "$local_choice" =~ ^[SsYy]$ ]]; then
        crack_digest_with_john "$kind" "$digest"
        return $?
    fi

    printf "Dica: SHA256 raramente aparece em bases públicas. Use John (opção 2).\n"
    return 1
}

lookup_hash_menu() {
    local raw source_choice

    printf "%b\n" "${BLUE}${BOLD}=== CONSULTAR HASH ONLINE ===${RESET}\n"
    echo "  1) Usar o último hash extraído"
    echo "  2) Colar um MD5 / SHA1 / SHA256"
    echo "  0) Voltar"
    echo
    read -r -p "Opção: " source_choice

    case "$source_choice" in
        1)
            if [[ -n "${LAST_HASH:-}" && -f "$LAST_HASH" ]]; then
                raw="$(read_hash_content "$LAST_HASH")"
            else
                error "Nenhum hash extraído nesta sessão."
                pause_menu
                return
            fi
            ;;
        2)
            read -r -p "Cole o hash: " raw
            ;;
        0|"")
            return
            ;;
        *)
            error "Opção inválida."
            pause_menu
            return
            ;;
    esac

    lookup_hash_online "$raw"
    pause_menu
}

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

safe_name() {
    local value="$1"
    value="${value##*/}"
    value="${value// /_}"
    value="$(printf '%s' "$value" | tr -cd '[:alnum:]_.-')"
    printf '%s' "${value:-arquivo}"
}

add_history() {
    local file="$1"
    local type="$2"
    local tool="$3"
    local output="$4"
    local status="$5"

    local d h
    d="$(date '+%Y-%m-%d')"
    h="$(date '+%H:%M:%S')"

    printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
        "$d" "$h" "$file" "$type" "$tool" "$output" "$status" >> "$HISTORY_FILE"
}

banner() {
    clear 2>/dev/null || true
    printf "%b\n" "${BLUE}${BOLD}"
    printf "╔════════════════════════════════════════════════════════════╗\n"
    printf "║                     EXTRATOR                              ║\n"
    printf "║  Detecção • Extração • Recriptografia • Wordlists         ║\n"
    printf "║                       BYPASS                              ║\n" "$VERSION"
    printf "╚════════════════════════════════════════════════════════════╝\n"
    printf "%b\n" "${RESET}"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# ---------- Detecção automática ----------
detect_type() {
    local file="$1"
    local mime ext

    if check_command file; then
        mime="$(file -b --mime-type "$file" 2>/dev/null)"
    else
        mime=""
    fi

    ext="${file##*.}"
    ext="${ext,,}"

    case "$ext" in
        pdf) printf '%s|%s\n' "PDF" "pdf2john"; return 0 ;;
        zip) printf '%s|%s\n' "ZIP" "zip2john"; return 0 ;;
        rar) printf '%s|%s\n' "RAR" "rar2john"; return 0 ;;
        7z)  printf '%s|%s\n' "7-ZIP" "7z2john"; return 0 ;;
    esac

    case "$mime" in
        application/pdf) printf '%s|%s\n' "PDF" "pdf2john"; return 0 ;;
        application/zip) printf '%s|%s\n' "ZIP" "zip2john"; return 0 ;;
        application/x-rar*) printf '%s|%s\n' "RAR" "rar2john"; return 0 ;;
        application/x-7z-compressed) printf '%s|%s\n' "7-ZIP" "7z2john"; return 0 ;;
    esac

    printf '%s|%s\n' "DESCONHECIDO" ""
}

find_in_candidates() {
    local name="$1"
    shift
    local candidate
    for candidate in "$@"; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_extractor() {
    local tool="$1"
    local john_path john_dir script_dir script_parent
    local candidates=()

    if check_command "$tool"; then
        command -v "$tool"
        return 0
    fi

    if check_command john; then
        john_path="$(command -v john)"
        john_dir="$(dirname "$(readlink -f "$john_path" 2>/dev/null || printf '%s' "$john_path")")"
        candidates+=(
            "$john_dir/$tool"
            "$john_dir/run/$tool"
            "$john_dir/../run/$tool"
            "$john_dir/../share/john/$tool"
        )
    fi

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    script_parent="$(dirname "$script_dir")"
    candidates+=(
        "$script_dir/$tool"
        "$script_dir/run/$tool"
        "$script_parent/run/$tool"
        "$script_parent/$tool"
    )

    candidates+=(
        "/usr/share/john/$tool"
        "/usr/lib/john/$tool"
        "/usr/libexec/john/$tool"
        "/opt/john/run/$tool"
        "/opt/john/$tool"
        "/usr/local/share/john/$tool"
        "/usr/local/libexec/john/$tool"
        "/usr/local/bin/$tool"
    )

    find_in_candidates "$tool" "${candidates[@]}"
}

find_john() {
    local candidate
    local script_dir script_parent

    if check_command john; then
        command -v john
        return 0
    fi

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    script_parent="$(dirname "$script_dir")"

    local candidates=(
        "$script_dir/john"
        "$script_dir/run/john"
        "$script_parent/john"
        "$script_parent/run/john"
        "/usr/bin/john"
        "/usr/sbin/john"
        "/usr/local/bin/john"
        "/usr/share/john/run/john"
        "/usr/lib/john/john"
        "/usr/libexec/john/john"
        "/opt/john/run/john"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

find_crunch() {
    local candidate
    local script_dir script_parent

    if check_command crunch; then
        command -v crunch
        return 0
    fi

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    script_parent="$(dirname "$script_dir")"

    local candidates=(
        "$script_dir/crunch"
        "$script_parent/crunch"
        "/usr/bin/crunch"
        "/usr/local/bin/crunch"
        "/opt/crunch/crunch"
        "/usr/share/crunch/crunch"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}


find_qpdf() {
    if check_command qpdf; then
        command -v qpdf
        return 0
    fi
    local candidate
    for candidate in /usr/bin/qpdf /usr/local/bin/qpdf /opt/qpdf/bin/qpdf; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_7z() {
    if check_command 7z; then
        command -v 7z
        return 0
    fi
    if check_command 7za; then
        command -v 7za
        return 0
    fi
    local candidate
    for candidate in /usr/bin/7z /usr/bin/7za /usr/local/bin/7z /usr/local/bin/7za; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_rar() {
    if check_command rar; then
        command -v rar
        return 0
    fi
    local candidate
    for candidate in /usr/bin/rar /usr/local/bin/rar; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

find_unrar() {
    if check_command unrar; then
        command -v unrar
        return 0
    fi
    local candidate
    for candidate in /usr/bin/unrar /usr/local/bin/unrar; do
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

is_http_url() {
    local value="$1"
    [[ "$value" =~ ^https?://[^[:space:]]+$ ]]
}

find_downloader() {
    if check_command curl; then
        printf '%s\n' "curl"
        return 0
    fi
    if check_command wget; then
        printf '%s\n' "wget"
        return 0
    fi
    return 1
}

filename_from_url() {
    local url="$1"
    local name

    name="${url%%\?*}"
    name="${name%%\#*}"
    name="${name%/}"
    name="${name##*/}"
    name="$(printf '%s' "$name" | tr -cd '[:alnum:]_.-')"
    printf '%s' "${name:-download.bin}"
}

confirm_authorized_url() {
    local confirm
    printf "\n%b\n" "${YELLOW}Somente baixe arquivos seus ou com autorização explícita.${RESET}"
    printf "Esta função não ataca sites, logins ou páginas de terceiros.\n"
    read -r -p "Confirma que você tem autorização para este link? (s/N): " confirm
    [[ "$confirm" =~ ^[SsYy]$ ]]
}

download_from_url() {
    local url="$1"
    local downloader dest name http_code

    downloader="$(find_downloader)" || {
        error "Nenhum downloader encontrado (curl ou wget)."
        warn "Instale: sudo apt install curl"
        return 1
    }

    name="$(filename_from_url "$url")"
    dest="${DOWNLOAD_DIR}/$(date '+%Y%m%d_%H%M%S')_${name}"

    info "Baixando arquivo do link..."
    printf "URL      : %s\n" "$url"
    printf "Destino  : %s\n" "$dest"

    if [[ "$downloader" == "curl" ]]; then
        http_code="$(
            curl -L --fail --silent --show-error \
                --max-filesize "$MAX_DOWNLOAD_BYTES" \
                --max-time 120 \
                --connect-timeout 20 \
                -A "ExtratorPRO/3.3 (auditoria autorizada)" \
                -o "$dest" \
                -w '%{http_code}' \
                "$url"
        )" || {
            error "Falha no download (HTTP ${http_code:-erro de rede})."
            rm -f "$dest"
            return 1
        }
        if [[ ! "$http_code" =~ ^2 ]]; then
            error "O servidor respondeu HTTP $http_code."
            rm -f "$dest"
            return 1
        fi
    else
        wget --quiet --max-redirect=5 --timeout=120 \
            --content-disposition \
            -O "$dest" \
            "$url" || {
            error "Falha no download com wget."
            rm -f "$dest"
            return 1
        }
    fi

    if [[ ! -s "$dest" ]]; then
        error "O download terminou, mas o arquivo está vazio."
        rm -f "$dest"
        return 1
    fi

    success "Arquivo baixado: $dest ($(du -h "$dest" | cut -f1))"
    SELECTED_FILE="$dest"
    LAST_URL="$url"
    return 0
}

choose_url() {
    local url

    printf "%b\n" "${WHITE}Informe o link direto do arquivo (http/https):${RESET}"
    printf "Exemplo: https://exemplo.com/arquivo.zip\n"
    read -r -p "URL: " url

    [[ -n "$url" ]] || { error "Nenhuma URL informada."; return 1; }

    is_http_url "$url" || {
        error "URL inválida. Use somente http:// ou https:// sem espaços."
        return 1
    }

    confirm_authorized_url || {
        warn "Operação cancelada."
        return 1
    }

    download_from_url "$url"
}

resolve_existing_file() {
    local input="$1"
    local resolved=""

    if [[ "$input" == "~/"* ]]; then
        input="${HOME}/${input#~/}"
    fi

    if [[ -f "$input" ]]; then
        resolved="$(realpath -e -- "$input" 2>/dev/null || true)"
    elif [[ ! "$input" = /* && -f "./$input" ]]; then
        resolved="$(realpath -e -- "./$input" 2>/dev/null || true)"
    fi

    [[ -n "$resolved" ]] || return 1
    printf '%s\n' "$resolved"
}

choose_file() {
    local file resolved

    printf "%b\n" "${WHITE}Informe o arquivo ou o link (http/https):${RESET}"
    printf "Diretório atual: %s\n" "$(pwd -P)"
    read -r -p "Caminho, nome ou URL: " file

    [[ -n "$file" ]] || { error "Nenhum arquivo informado."; return 1; }

    if is_http_url "$file"; then
        confirm_authorized_url || {
            warn "Operação cancelada."
            return 1
        }
        download_from_url "$file"
        return $?
    fi

    resolved="$(resolve_existing_file "$file")" || {
        error "Arquivo não encontrado: $file"
        return 1
    }

    [[ -r "$resolved" ]] || {
        error "O arquivo não possui permissão de leitura: $resolved"
        return 1
    }

    SELECTED_FILE="$resolved"
    info "Arquivo localizado em: $SELECTED_FILE"
    return 0
}

# ---------- Extração ----------
extract_hash() {
    local file="$1"
    local type="$2"
    local tool="$3"
    local output="$4"
    local temp

    temp="$(mktemp)" || {
        error "Falha ao criar arquivo temporário."
        return 1
    }

    info "Executando: $tool"
    if "$tool" "$file" > "$temp" 2> "${temp}.err"; then
        if [[ ! -s "$temp" ]]; then
            rm -f "$temp" "${temp}.err"
            error "A ferramenta terminou, mas não gerou hash."
            return 1
        fi

        mv "$temp" "$output" || {
            rm -f "$temp" "${temp}.err"
            error "Não foi possível salvar o hash."
            return 1
        }

        if [[ -s "${temp}.err" ]]; then
            warn "A ferramenta produziu mensagens de diagnóstico."
            sed 's/^/[ferramenta] /' "${temp}.err" >&2
        fi
        rm -f "${temp}.err"

        success "Hash extraído com sucesso."
        return 0
    fi

    if [[ -s "${temp}.err" ]]; then
        error "Mensagem da ferramenta:"
        sed 's/^/  /' "${temp}.err" >&2
    fi

    rm -f "$temp" "${temp}.err"
    return 1
}

new_extraction() {
    local type tool extractor output base status

    if ! choose_file; then
        pause_menu
        return
    fi

    type=""
    tool=""

    IFS='|' read -r type tool < <(detect_type "$SELECTED_FILE")

    printf "\n%b\n" "${BOLD}=== Detecção automática ===${RESET}"
    printf "Arquivo   : %s\n" "$SELECTED_FILE"
    printf "Tipo      : %s\n" "$type"
    printf "Extrator  : %s\n" "${tool:-não identificado}"

    if [[ -z "$tool" ]]; then
        warn "O tipo de arquivo não foi reconhecido automaticamente."
        printf "\nExtratores disponíveis: pdf2john, zip2john, rar2john, 7z2john\n"
        read -r -p "Digite manualmente o extrator: " tool
    fi

    extractor="$(find_extractor "$tool")" || {
        error "Extrator '$tool' não encontrado."
        warn "Verifique se o pacote do John the Ripper está instalado."
        add_history "$SELECTED_FILE" "$type" "$tool" "-" "EXTRATOR_NAO_ENCONTRADO"
        pause_menu
        return
    }

    base="$(safe_name "$SELECTED_FILE")"
    output="${HASH_DIR}/${base}_$(date '+%Y%m%d_%H%M%S').hash"

    printf "Extrator  : %s\n" "$extractor"
    printf "Saída     : %s\n\n" "$output"

    if extract_hash "$SELECTED_FILE" "$type" "$extractor" "$output"; then
        status="SUCESSO"
        add_history "$SELECTED_FILE" "$type" "$extractor" "$output" "$status"
        LAST_HASH="$output"
        LAST_FILE="$SELECTED_FILE"
        LAST_TYPE="$type"
        LAST_TOOL="$extractor"
        success "Resultado registrado no histórico."
        offer_copy_hash "$output"
    else
        status="FALHA"
        add_history "$SELECTED_FILE" "$type" "$extractor" "$output" "$status"
        error "Extração não concluída."
    fi

    pause_menu
}

new_extraction_from_url() {
    if ! choose_url; then
        pause_menu
        return
    fi

    # Reutiliza o fluxo de extração já carregado em SELECTED_FILE.
    local type tool extractor output base status

    type=""
    tool=""

    IFS='|' read -r type tool < <(detect_type "$SELECTED_FILE")

    printf "\n%b\n" "${BOLD}=== Detecção automática (URL) ===${RESET}"
    printf "Origem    : %s\n" "${LAST_URL:-link}"
    printf "Arquivo   : %s\n" "$SELECTED_FILE"
    printf "Tipo      : %s\n" "$type"
    printf "Extrator  : %s\n" "${tool:-não identificado}"

    if [[ -z "$tool" ]]; then
        warn "O tipo de arquivo não foi reconhecido automaticamente."
        printf "\nExtratores disponíveis: pdf2john, zip2john, rar2john, 7z2john\n"
        read -r -p "Digite manualmente o extrator: " tool
    fi

    extractor="$(find_extractor "$tool")" || {
        error "Extrator '$tool' não encontrado."
        add_history "${LAST_URL:-$SELECTED_FILE}" "$type" "$tool" "-" "EXTRATOR_NAO_ENCONTRADO"
        pause_menu
        return
    }

    base="$(safe_name "$SELECTED_FILE")"
    output="${HASH_DIR}/${base}_$(date '+%Y%m%d_%H%M%S').hash"

    printf "Extrator  : %s\n" "$extractor"
    printf "Saída     : %s\n\n" "$output"

    if extract_hash "$SELECTED_FILE" "$type" "$extractor" "$output"; then
        status="SUCESSO"
        add_history "${LAST_URL:-$SELECTED_FILE}" "$type" "$extractor" "$output" "$status"
        LAST_HASH="$output"
        LAST_FILE="$SELECTED_FILE"
        LAST_TYPE="$type"
        LAST_TOOL="$extractor"
        success "Resultado registrado no histórico."
        offer_copy_hash "$output"
    else
        status="FALHA"
        add_history "${LAST_URL:-$SELECTED_FILE}" "$type" "$extractor" "$output" "$status"
        error "Extração não concluída."
    fi

    pause_menu
}

# ---------- Wordlist (Crunch) ----------
list_available_wordlists() {
    local idx=1
    local f

    WORDLIST_OPTIONS=()

    if [[ -f "$DEFAULT_WORDLIST" ]]; then
        WORDLIST_OPTIONS+=("$DEFAULT_WORDLIST")
        printf "  %2d) %s  (padrão do sistema)\n" "$idx" "$DEFAULT_WORDLIST"
        idx=$((idx + 1))
    fi

    if [[ -d "$WORDLIST_DIR" ]]; then
        while IFS= read -r -d '' f; do
            WORDLIST_OPTIONS+=("$f")
            printf "  %2d) %s\n" "$idx" "$f"
            idx=$((idx + 1))
        done < <(find "$WORDLIST_DIR" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null | sort -z)
    fi

    if [[ -n "${LAST_WORDLIST:-}" && -f "$LAST_WORDLIST" ]]; then
        local already=0
        for existing in "${WORDLIST_OPTIONS[@]}"; do
            [[ "$existing" == "$LAST_WORDLIST" ]] && already=1 && break
        done
        if [[ $already -eq 0 ]]; then
            WORDLIST_OPTIONS+=("$LAST_WORDLIST")
            printf "  %2d) %s  (última usada)\n" "$idx" "$LAST_WORDLIST"
            idx=$((idx + 1))
        fi
    fi

    if [[ ${#WORDLIST_OPTIONS[@]} -eq 0 ]]; then
        warn "Nenhuma wordlist encontrada."
        return 1
    fi
    return 0
}

choose_wordlist() {
    local choice custom

    printf "\n%b\n" "${BOLD}=== SELEÇÃO DE WORDLIST ===${RESET}"
    printf "Escolha uma wordlist ou digite um caminho personalizado.\n\n"

    if list_available_wordlists; then
        printf "\n  %2d) Digitar caminho manualmente\n" "$(( ${#WORDLIST_OPTIONS[@]} + 1 ))"
        printf "  %2d) Gerar nova wordlist com Crunch\n" "$(( ${#WORDLIST_OPTIONS[@]} + 2 ))"
    else
        printf "  1) Digitar caminho manualmente\n"
        printf "  2) Gerar nova wordlist com Crunch\n"
    fi

    echo
    read -r -p "Opção [Enter = padrão do sistema se disponível]: " choice

    if [[ -z "$choice" ]]; then
        if [[ -f "$DEFAULT_WORDLIST" ]]; then
            SELECTED_WORDLIST="$DEFAULT_WORDLIST"
            return 0
        fi
        error "Wordlist padrão não encontrada. Escolha outra opção."
        return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#WORDLIST_OPTIONS[@]} )); then
        SELECTED_WORDLIST="${WORDLIST_OPTIONS[$((choice - 1))]}"
        return 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice == ${#WORDLIST_OPTIONS[@]} + 1 )); then
        read -r -p "Caminho da wordlist: " custom
        SELECTED_WORDLIST="$(resolve_existing_file "$custom")" || {
            error "Arquivo não encontrado: $custom"
            return 1
        }
        return 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice == ${#WORDLIST_OPTIONS[@]} + 2 )); then
        if generate_wordlist; then
            if [[ -n "${LAST_GENERATED_WORDLIST:-}" && -f "$LAST_GENERATED_WORDLIST" ]]; then
                SELECTED_WORDLIST="$LAST_GENERATED_WORDLIST"
                return 0
            fi
        fi
        return 1
    fi

    SELECTED_WORDLIST="$(resolve_existing_file "$choice")" || {
        error "Opção inválida ou arquivo não encontrado: $choice"
        return 1
    }
    return 0
}

generate_wordlist() {
    local crunch_bin min_len max_len charset charset_choice output_name output confirm
    local charset_lower="abcdefghijklmnopqrstuvwxyz"
    local charset_upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local charset_digits="0123456789"
    local charset_special='!@#$%&*()-_=+[]{}'
    local charset_alnum="${charset_lower}${charset_digits}"
    local charset_all="${charset_lower}${charset_upper}${charset_digits}${charset_special}"

    crunch_bin="$(find_crunch)" || {
        error "Crunch não foi encontrado."
        warn "Instale o pacote 'crunch' (ex: apt install crunch) ou coloque o executável no PATH."
        pause_menu
        return 1
    }

    printf "\n%b\n" "${BLUE}${BOLD}=== GERAR WORDLIST COM CRUNCH ===${RESET}"
    printf "Crunch : %s\n\n" "$crunch_bin"

    read -r -p "Tamanho mínimo (ex: 4): " min_len
    [[ "$min_len" =~ ^[0-9]+$ ]] && (( min_len >= 1 && min_len <= 20 )) || {
        error "Tamanho mínimo inválido (use número entre 1 e 20)."
        pause_menu
        return 1
    }

    read -r -p "Tamanho máximo (ex: 6): " max_len
    [[ "$max_len" =~ ^[0-9]+$ ]] && (( max_len >= min_len && max_len <= 20 )) || {
        error "Tamanho máximo inválido (deve ser >= mínimo e <= 20)."
        pause_menu
        return 1
    }

    printf "\n%b\n" "${BOLD}Conjuntos de caracteres:${RESET}"
    echo "  1) Letras minúsculas (a-z)"
    echo "  2) Letras maiúsculas (A-Z)"
    echo "  3) Apenas números (0-9)"
    echo "  4) Letras minúsculas + números"
    echo "  5) Letras maiúsculas + números"
    echo "  6) Todos (minúsculas + maiúsculas + números + especiais)"
    echo "  7) Personalizado"
    echo
    read -r -p "Escolha o conjunto [1]: " charset_choice
    charset_choice="${charset_choice:-1}"

    case "$charset_choice" in
        1) charset="$charset_lower" ;;
        2) charset="$charset_upper" ;;
        3) charset="$charset_digits" ;;
        4) charset="$charset_alnum" ;;
        5) charset="${charset_upper}${charset_digits}" ;;
        6) charset="$charset_all" ;;
        7)
            read -r -p "Digite os caracteres desejados: " charset
            [[ -n "$charset" ]] || {
                error "Conjunto de caracteres vazio."
                pause_menu
                return 1
            }
            ;;
        *)
            error "Opção inválida."
            pause_menu
            return 1
            ;;
    esac

    read -r -p "Nome do arquivo de saída (sem extensão) [wordlist]: " output_name
    output_name="$(safe_name "${output_name:-wordlist}")"
    output="${WORDLIST_DIR}/${output_name}_$(date '+%Y%m%d_%H%M%S').txt"

    local charset_len=${#charset}
    local estimate=0
    local i
    for ((i = min_len; i <= max_len; i++)); do
        estimate=$((estimate + charset_len ** i))
    done

    printf "\n%b\n" "${BOLD}Resumo da geração${RESET}"
    printf "Mínimo     : %s\n" "$min_len"
    printf "Máximo     : %s\n" "$max_len"
    printf "Charset    : %s (%d caracteres)\n" "$charset" "$charset_len"
    printf "Saída      : %s\n" "$output"
    if (( estimate > 0 && estimate < 1000000000 )); then
        printf "Estimativa : ~%s linhas\n" "$estimate"
    else
        printf "Estimativa : grande (pode demorar e ocupar muito espaço)\n"
    fi

    if (( estimate > 50000000 )); then
        warn "A wordlist estimada é muito grande. Isso pode demorar e consumir bastante disco."
    fi

    printf "\n"
    read -r -p "Confirmar geração? (s/N): " confirm
    if [[ ! "$confirm" =~ ^[SsYy]$ ]]; then
        warn "Operação cancelada."
        pause_menu
        return 1
    fi

    info "Gerando wordlist com Crunch..."
    if "$crunch_bin" "$min_len" "$max_len" "$charset" -o "$output"; then
        if [[ -s "$output" ]]; then
            local lines size
            lines="$(wc -l < "$output" 2>/dev/null || echo '?')"
            size="$(du -h "$output" 2>/dev/null | cut -f1 || echo '?')"
            success "Wordlist gerada com sucesso."
            printf "Arquivo : %s\n" "$output"
            printf "Linhas  : %s\n" "$lines"
            printf "Tamanho : %s\n" "$size"
            LAST_GENERATED_WORDLIST="$output"
            LAST_WORDLIST="$output"
            pause_menu
            return 0
        else
            error "Arquivo gerado está vazio."
            rm -f "$output"
            pause_menu
            return 1
        fi
    else
        error "Falha ao executar o Crunch."
        rm -f "$output"
        pause_menu
        return 1
    fi
}

list_wordlists() {
    printf "%b\n" "${BLUE}${BOLD}=== WORDLISTS DISPONÍVEIS ===${RESET}\n"

    printf "Padrão do sistema:\n"
    if [[ -f "$DEFAULT_WORDLIST" ]]; then
        printf "  %s\n" "$DEFAULT_WORDLIST"
    else
        warn "  (não encontrada)"
    fi

    printf "\nGeradas pelo usuário (%s):\n" "$WORDLIST_DIR"
    if ! find "$WORDLIST_DIR" -maxdepth 1 -type f -name '*.txt' -printf '  %TY-%Tm-%Td %TH:%TM  %p  (%s bytes)\n' 2>/dev/null | sort -r; then
        warn "  Nenhuma wordlist gerada ainda."
    fi

    if [[ -n "${LAST_WORDLIST:-}" && -f "$LAST_WORDLIST" ]]; then
        printf "\nÚltima usada: %s\n" "$LAST_WORDLIST"
    fi

    pause_menu
}

# ---------- John ----------
run_john_menu() {
    local hash wordlist custom john_bin confirm rc
    local john_dir

    john_bin="$(find_john)" || {
        error "John the Ripper não foi encontrado."
        warn "Instale o John ou coloque o executável no PATH."
        pause_menu
        return
    }

    john_dir="$(dirname -- "$john_bin")"
    printf "%b\n" "${BLUE}${BOLD}=== CONFIGURAÇÃO DO JOHN ===${RESET}"
    printf "John       : %s\n" "$john_bin"
    printf "Diretório  : %s\n\n" "$john_dir"

    if [[ -n "${LAST_HASH:-}" && -f "$LAST_HASH" ]]; then
        hash="$LAST_HASH"
        info "Usando o último hash gerado: $hash"
        read -r -p "Pressione ENTER para aceitar ou informe outro hash: " custom
        [[ -n "$custom" ]] && hash="$custom"
    else
        read -r -p "Caminho do arquivo de hash: " hash
    fi

    hash="$(resolve_existing_file "$hash")" || {
        error "Arquivo de hash não encontrado."
        pause_menu
        return
    }

    [[ -r "$hash" ]] || {
        error "Arquivo de hash sem permissão de leitura."
        pause_menu
        return
    }

    if ! choose_wordlist; then
        pause_menu
        return
    fi
    wordlist="$SELECTED_WORDLIST"

    [[ -r "$wordlist" ]] || {
        error "Wordlist sem permissão de leitura: $wordlist"
        pause_menu
        return
    }

    printf "\n%b\n" "${BOLD}Arquivos selecionados${RESET}"
    printf "Hash     : %s\n" "$hash"
    printf "Wordlist : %s\n" "$wordlist"
    printf "John     : %s\n" "$john_bin"

    printf "\n%b\n" "${YELLOW}A execução do John será iniciada com a wordlist informada.${RESET}"
    read -r -p "Confirmar? (s/N): " confirm
    if [[ ! "$confirm" =~ ^[SsYy]$ ]]; then
        warn "Operação cancelada."
        pause_menu
        return
    fi

    printf "\n%b\n" "${BLUE}${BOLD}=== John the Ripper ===${RESET}"
    info "Executando o binário localizado automaticamente."
    printf "\n"

    "$john_bin" --wordlist="$wordlist" "$hash"
    rc=$?

    printf "\n"
    if [[ $rc -eq 0 ]]; then
        success "John finalizado."
    else
        warn "John terminou com código de retorno: $rc"
    fi

    printf "\n%b\n" "${BOLD}Resultado (--show)${RESET}"
    local shown
    shown="$("$john_bin" --show "$hash" 2>/dev/null || true)"
    printf '%s\n' "$shown"

    if [[ "$shown" == *:* && "$shown" != *"0 password hashes cracked"* && "$shown" != *"No password hashes loaded"* ]]; then
        LAST_PLAINTEXT="${shown#*:}"
        LAST_PLAINTEXT="${LAST_PLAINTEXT%%$'\n'*}"
        LAST_PLAINTEXT="${LAST_PLAINTEXT%%:*}"
        if [[ -n "$LAST_PLAINTEXT" ]]; then
            success "Senha recuperada nesta sessão: (disponível para opção 13)"
        fi
    fi

    LAST_HASH="$hash"
    LAST_JOHN="$john_bin"
    LAST_WORDLIST="$wordlist"
    pause_menu
}

# ---------- Histórico ----------
show_history() {
    printf "%b\n" "${BLUE}${BOLD}=== HISTÓRICO ===${RESET}"

    if [[ ! -s "$HISTORY_FILE" ]]; then
        warn "Nenhum registro encontrado."
        pause_menu
        return
    fi

    if check_command column; then
        column -t -s ',' < "$HISTORY_FILE" | tail -n 21
    else
        tail -n 20 "$HISTORY_FILE"
    fi

    pause_menu
}

clear_history() {
    printf "%b\n" "${YELLOW}Esta opção remove o histórico registrado pelo programa.${RESET}"
    read -r -p "Confirmar limpeza? (s/N): " confirm

    if [[ "$confirm" =~ ^[SsYy]$ ]]; then
        printf '%s\n' 'data,hora,arquivo,tipo,ferramenta,hash_saida,status' > "$HISTORY_FILE"
        success "Histórico limpo."
    else
        warn "Operação cancelada."
    fi

    pause_menu
}

# ---------- Relatórios ----------
html_escape() {
    sed \
        -e 's/&/\&/g' \
        -e 's/</\</g' \
        -e 's/>/\>/g' \
        -e 's/"/\"/g' \
        -e "s/'/\&#39;/g"
}

generate_txt_report() {
    local file="$1"
    local now
    now="$(timestamp)"

    {
        echo "============================================================"
        echo "                 RELATÓRIO - EXTRATOR PRO"
        echo "============================================================"
        echo "Versão: $VERSION"
        echo "Data: $now"
        echo
        echo "RESUMO"
        echo "------------------------------------------------------------"
        echo "Registros no histórico: $(($(wc -l < "$HISTORY_FILE") - 1))"
        echo
        echo "ÚLTIMOS REGISTROS"
        echo "------------------------------------------------------------"
        tail -n 20 "$HISTORY_FILE"
        echo
        echo "DIRETÓRIOS"
        echo "------------------------------------------------------------"
        echo "Base: $BASE_DIR"
        echo "Hashes: $HASH_DIR"
        echo "Wordlists: $WORDLIST_DIR"
        echo "Downloads: $DOWNLOAD_DIR"
        echo "Relatórios: $REPORT_DIR"
        echo
        echo "OBSERVAÇÃO"
        echo "------------------------------------------------------------"
        echo "Use esta ferramenta somente em arquivos próprios ou autorizados."
    } > "$file"
}

generate_html_report() {
    local file="$1"
    local now rows

    now="$(timestamp)"
    rows=""

    while IFS=',' read -r date time archive type tool hash status; do
        [[ "$date" == "data" ]] && continue
        rows+="<tr><td>${date//\"/}</td><td>${time//\"/}</td><td>${archive//\"/}</td><td>${type//\"/}</td><td>${tool//\"/}</td><td>${hash//\"/}</td><td>${status//\"/}</td></tr>"
    done < "$HISTORY_FILE"

    cat > "$file" <<EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Relatório - Extrator PRO</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f4f6f8;color:#222}
header{background:#17202a;color:white;padding:28px}
main{padding:24px}
.card{background:white;border-radius:10px;padding:20px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
th{background:#e9eef2}
.ok{font-weight:bold}
.small{color:#666;font-size:12px}
code{word-break:break-all}
</style>
</head>
<body>
<header>
<h1>Extrator PRO</h1>
<p>Relatório de operações</p>
</header>
<main>
<div class="card">
<h2>Resumo</h2>
<p><strong>Versão:</strong> $VERSION</p>
<p><strong>Gerado em:</strong> $now</p>
<p><strong>Total de registros:</strong> $(($(wc -l < "$HISTORY_FILE") - 1))</p>
</div>
<div class="card">
<h2>Histórico</h2>
<table>
<thead>
<tr><th>Data</th><th>Hora</th><th>Arquivo</th><th>Tipo</th><th>Ferramenta</th><th>Hash</th><th>Status</th></tr>
</thead>
<tbody>
$rows
</tbody>
</table>
</div>
<div class="card small">
<strong>Nota:</strong> utilize a ferramenta somente em arquivos próprios ou para os quais exista autorização.
</div>
</main>
</body>
</html>
EOF
}

generate_reports() {
    local stamp txt html

    stamp="$(date '+%Y%m%d_%H%M%S')"
    txt="${REPORT_DIR}/relatorio_${stamp}.txt"
    html="${REPORT_DIR}/relatorio_${stamp}.html"

    generate_txt_report "$txt"
    generate_html_report "$html"

    success "Relatório TXT: $txt"
    success "Relatório HTML: $html"

    LAST_TXT="$txt"
    LAST_HTML="$html"
    pause_menu
}

list_files() {
    printf "%b\n" "${BLUE}${BOLD}=== ARQUIVOS DE HASH ===${RESET}"

    if ! find "$HASH_DIR" -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r; then
        warn "Não foi possível listar os arquivos."
    fi

    pause_menu
}

show_status() {
    printf "%b\n" "${BLUE}${BOLD}=== STATUS DO AMBIENTE ===${RESET}\n"

    printf "Sistema      : "
    if check_command uname; then uname -srmo; else echo "indisponível"; fi

    printf "Bash         : %s\n" "${BASH_VERSION%%(*}"
    printf "Diretório    : %s\n" "$BASE_DIR"
    printf "Histórico    : %s\n" "$HISTORY_FILE"
    printf "Wordlists    : %s\n" "$WORDLIST_DIR"
    printf "Downloads    : %s\n" "$DOWNLOAD_DIR"
    printf "John         : "
    if john_path="$(find_john 2>/dev/null)"; then
        printf "%s\n" "$john_path"
        printf "Versão       : "
        "$john_path" --version 2>&1 | head -n 1
    else
        echo "não encontrado"
    fi

    printf "Crunch       : "
    if crunch_path="$(find_crunch 2>/dev/null)"; then
        printf "%s\n" "$crunch_path"
    else
        echo "não encontrado"
    fi

    printf "Download     : "
    if dl="$(find_downloader 2>/dev/null)"; then
        printf "%s\n" "$dl"
    else
        echo "não encontrado (instale curl)"
    fi

    for tool in pdf2john zip2john rar2john 7z2john; do
        printf "%-10s: " "$tool"
        if find_extractor "$tool" >/dev/null 2>&1; then
            echo "disponível"
        else
            echo "não encontrado"
        fi
    done

    printf "\nqpdf         : "
    if qpdf_path="$(find_qpdf 2>/dev/null)"; then
        printf "%s\n" "$qpdf_path"
    else
        echo "não encontrado (necessário para recriptografar PDF)"
    fi

    printf "7z           : "
    if z7_path="$(find_7z 2>/dev/null)"; then
        printf "%s\n" "$z7_path"
    else
        echo "não encontrado (recomendado para ZIP/7z)"
    fi

    printf "rar          : "
    if rar_path="$(find_rar 2>/dev/null)"; then
        printf "%s\n" "$rar_path"
    else
        echo "não encontrado (necessário para recriptografar RAR)"
    fi

    printf "\nWordlist padrão: %s\n" "$DEFAULT_WORDLIST"
    if [[ -f "$DEFAULT_WORDLIST" ]]; then
        echo "Status: disponível"
    else
        echo "Status: não encontrada"
    fi

    local wl_count
    wl_count="$(find "$WORDLIST_DIR" -maxdepth 1 -type f -name '*.txt' 2>/dev/null | wc -l)"
    printf "Wordlists geradas: %s\n" "$wl_count"
    printf "Recriptografados: %s\n" "$RECRYPT_DIR"

    pause_menu
}


# ---------- Recriptografia (exige senha atual) ----------
# Gera um NOVO arquivo com senha nova. Nunca remove proteção sem a senha atual.
# Uso exclusivo em arquivos próprios ou com autorização explícita.

prompt_passwords() {
    local old_default="${1:-}"
    local old_pass new_pass new_pass2

    if [[ -n "$old_default" ]]; then
        printf "Senha atual detectada da sessão (John): %b%s%b\n" "$GREEN" "(preenchida)" "$RESET"
        read -r -p "Senha atual [Enter = usar a recuperada]: " old_pass
        old_pass="${old_pass:-$old_default}"
    else
        read -r -s -p "Senha atual do arquivo: " old_pass
        printf "\n"
    fi

    [[ -n "$old_pass" ]] || {
        error "Senha atual é obrigatória. Não é possível recriptografar sem ela."
        return 1
    }

    read -r -s -p "Nova senha: " new_pass
    printf "\n"
    [[ -n "$new_pass" ]] || {
        error "Nova senha não pode ser vazia."
        return 1
    }

    read -r -s -p "Confirme a nova senha: " new_pass2
    printf "\n"

    if [[ "$new_pass" != "$new_pass2" ]]; then
        error "As novas senhas não coincidem."
        return 1
    fi

    if [[ "$old_pass" == "$new_pass" ]]; then
        warn "A nova senha é igual à atual. Continuando mesmo assim."
    fi

    RECRYPT_OLD_PASS="$old_pass"
    RECRYPT_NEW_PASS="$new_pass"
    return 0
}

reencrypt_pdf() {
    local input="$1"
    local output="$2"
    local qpdf_bin tmp_dec

    qpdf_bin="$(find_qpdf)" || {
        error "qpdf não encontrado. Instale: sudo apt install qpdf"
        return 1
    }

    tmp_dec="$(mktemp "${TMPDIR:-/tmp}/extrator-pdf-XXXXXX.pdf")" || return 1

    info "Descriptografando PDF com a senha atual..."
    if ! "$qpdf_bin" --password="$RECRYPT_OLD_PASS" --decrypt "$input" "$tmp_dec" 2>/dev/null; then
        rm -f "$tmp_dec"
        error "Falha ao descriptografar. Senha atual incorreta ou PDF inválido."
        return 1
    fi

    info "Criptografando com a nova senha (AES-256)..."
    if ! "$qpdf_bin" --encrypt "$RECRYPT_NEW_PASS" "$RECRYPT_NEW_PASS" 256 -- "$tmp_dec" "$output" 2>/dev/null; then
        rm -f "$tmp_dec"
        error "Falha ao aplicar a nova senha no PDF."
        return 1
    fi

    rm -f "$tmp_dec"
    return 0
}

reencrypt_zip() {
    local input="$1"
    local output="$2"
    local z7_bin tmpdir

    z7_bin="$(find_7z)" || true

    if [[ -n "$z7_bin" ]]; then
        tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/extrator-zip-XXXXXX")" || return 1
        info "Extraindo ZIP com 7z (senha atual)..."
        if ! "$z7_bin" x -y -p"$RECRYPT_OLD_PASS" -o"$tmpdir" "$input" >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            error "Falha ao extrair ZIP. Senha atual incorreta ou arquivo corrompido."
            return 1
        fi
        info "Criando novo ZIP com a nova senha..."
        rm -f "$output"
        if ! "$z7_bin" a -tzip -p"$RECRYPT_NEW_PASS" -mem=AES256 "$output" "$tmpdir"/* >/dev/null 2>&1; then
            rm -rf "$tmpdir"
            error "Falha ao criar o novo ZIP."
            return 1
        fi
        rm -rf "$tmpdir"
        return 0
    fi

    if ! check_command unzip || ! check_command zip; then
        error "Nem 7z nem (unzip+zip) estão disponíveis."
        warn "Instale: sudo apt install p7zip-full   ou   unzip zip"
        return 1
    fi

    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/extrator-zip-XXXXXX")" || return 1
    info "Extraindo ZIP com unzip (senha atual)..."
    if ! unzip -P "$RECRYPT_OLD_PASS" -q -o "$input" -d "$tmpdir" 2>/dev/null; then
        rm -rf "$tmpdir"
        error "Falha ao extrair ZIP. Senha atual incorreta."
        return 1
    fi

    info "Criando novo ZIP com zip (senha nova)..."
    rm -f "$output"
    (
        cd "$tmpdir" || exit 1
        zip -r -P "$RECRYPT_NEW_PASS" "$output" . >/dev/null 2>&1
    ) || {
        rm -rf "$tmpdir"
        error "Falha ao criar o novo ZIP."
        return 1
    }
    rm -rf "$tmpdir"
    warn "ZIP criado com criptografia tradicional do 'zip' (mais fraca que AES). Prefira instalar p7zip-full."
    return 0
}

reencrypt_7z() {
    local input="$1"
    local output="$2"
    local z7_bin tmpdir

    z7_bin="$(find_7z)" || {
        error "7z não encontrado. Instale: sudo apt install p7zip-full"
        return 1
    }

    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/extrator-7z-XXXXXX")" || return 1

    info "Extraindo 7z com a senha atual..."
    if ! "$z7_bin" x -y -p"$RECRYPT_OLD_PASS" -o"$tmpdir" "$input" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        error "Falha ao extrair 7z. Senha atual incorreta ou arquivo inválido."
        return 1
    fi

    info "Criando novo 7z com a nova senha..."
    rm -f "$output"
    if ! "$z7_bin" a -t7z -p"$RECRYPT_NEW_PASS" -mhe=on "$output" "$tmpdir"/* >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        error "Falha ao criar o novo arquivo 7z."
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

reencrypt_rar() {
    local input="$1"
    local output="$2"
    local rar_bin unrar_bin tmpdir

    rar_bin="$(find_rar)" || {
        error "rar (WinRAR CLI) não encontrado. É necessário para criar RAR com senha."
        warn "unrar sozinho só extrai; para recriptografar instale o pacote 'rar'."
        return 1
    }

    unrar_bin="$(find_unrar)" || unrar_bin="$rar_bin"

    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/extrator-rar-XXXXXX")" || return 1

    info "Extraindo RAR com a senha atual..."
    if ! "$unrar_bin" x -p"$RECRYPT_OLD_PASS" -y "$input" "$tmpdir/" >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        error "Falha ao extrair RAR. Senha atual incorreta ou arquivo inválido."
        return 1
    fi

    info "Criando novo RAR com a nova senha..."
    rm -f "$output"
    if ! "$rar_bin" a -hp"$RECRYPT_NEW_PASS" -y "$output" "$tmpdir"/* >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        error "Falha ao criar o novo RAR."
        return 1
    fi

    rm -rf "$tmpdir"
    return 0
}

reencrypt_menu() {
    local file type tool output base status confirm
    local old_default=""

    printf "%b\n" "${BLUE}${BOLD}=== RECRIPTOGRAFAR COM NOVA SENHA ===${RESET}"
    printf "\n%b\n" "${YELLOW}Esta função EXIGE a senha atual do arquivo.${RESET}"
    printf "Ela gera um NOVO arquivo protegido com a senha que você definir.\n"
    printf "O arquivo original NÃO é alterado nem apagado.\n"
    printf "Use somente em arquivos seus ou com autorização explícita.\n\n"

    if [[ -n "${LAST_FILE:-}" && -f "$LAST_FILE" ]]; then
        info "Último arquivo da sessão: $LAST_FILE"
        read -r -p "Usar este arquivo? (S/n): " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            SELECTED_FILE="$LAST_FILE"
        else
            if ! choose_file; then
                pause_menu
                return
            fi
        fi
    else
        if ! choose_file; then
            pause_menu
            return
        fi
    fi

    file="$SELECTED_FILE"
    IFS='|' read -r type tool < <(detect_type "$file")

    printf "\n%b\n" "${BOLD}Arquivo selecionado${RESET}"
    printf "Caminho : %s\n" "$file"
    printf "Tipo    : %s\n" "$type"

    case "$type" in
        PDF|ZIP|RAR|7-ZIP) ;;
        *)
            error "Tipo não suportado para recriptografia: $type"
            printf "Suportados: PDF (qpdf), ZIP (7z/zip), 7-ZIP (7z), RAR (rar).\n"
            pause_menu
            return
            ;;
    esac

    if [[ -n "${LAST_PLAINTEXT:-}" ]]; then
        old_default="$LAST_PLAINTEXT"
    fi

    if ! prompt_passwords "$old_default"; then
        pause_menu
        return
    fi

    base="$(safe_name "$file")"
    case "$type" in
        PDF)   output="${RECRYPT_DIR}/${base}_nova_$(date '+%Y%m%d_%H%M%S').pdf" ;;
        ZIP)   output="${RECRYPT_DIR}/${base}_nova_$(date '+%Y%m%d_%H%M%S').zip" ;;
        RAR)   output="${RECRYPT_DIR}/${base}_nova_$(date '+%Y%m%d_%H%M%S').rar" ;;
        7-ZIP) output="${RECRYPT_DIR}/${base}_nova_$(date '+%Y%m%d_%H%M%S').7z" ;;
    esac

    printf "\n%b\n" "${BOLD}Resumo${RESET}"
    printf "Entrada  : %s\n" "$file"
    printf "Saída    : %s\n" "$output"
    printf "Tipo     : %s\n" "$type"
    printf "\n"
    read -r -p "Confirmar recriptografia? (s/N): " confirm
    if [[ ! "$confirm" =~ ^[SsYy]$ ]]; then
        warn "Operação cancelada."
        RECRYPT_OLD_PASS=""
        RECRYPT_NEW_PASS=""
        pause_menu
        return
    fi

    status="FALHA"
    case "$type" in
        PDF)
            if reencrypt_pdf "$file" "$output"; then status="SUCESSO"; fi
            ;;
        ZIP)
            if reencrypt_zip "$file" "$output"; then status="SUCESSO"; fi
            ;;
        7-ZIP)
            if reencrypt_7z "$file" "$output"; then status="SUCESSO"; fi
            ;;
        RAR)
            if reencrypt_rar "$file" "$output"; then status="SUCESSO"; fi
            ;;
    esac

    RECRYPT_OLD_PASS=""
    RECRYPT_NEW_PASS=""

    if [[ "$status" == "SUCESSO" && -s "$output" ]]; then
        success "Arquivo recriptografado com sucesso."
        printf "Novo arquivo: %s (%s)\n" "$output" "$(du -h "$output" | cut -f1)"
        add_history "$file" "$type" "recriptografar" "$output" "$status"
        LAST_FILE="$output"
    else
        error "Recriptografia não concluída."
        rm -f "$output"
        add_history "$file" "$type" "recriptografar" "-" "$status"
    fi

    pause_menu
}

menu() {
    while true; do
        banner

        printf "%b\n" "${WHITE}${BOLD}MENU PRINCIPAL${RESET}"
        echo
        echo "  1) Extrair hash (arquivo local ou URL)"
        echo "  2) Executar John the Ripper"
        echo "  3) Exibir histórico"
        echo "  4) Gerar relatório TXT + HTML"
        echo "  5) Listar hashes gerados"
        echo "  6) Status / diagnóstico do ambiente"
        echo "  7) Limpar histórico"
        echo "  8) Gerar wordlist com Crunch"
        echo "  9) Listar wordlists disponíveis"
        echo " 10) Extrair hash a partir de um link/URL"
        echo " 11) Copiar último hash"
        echo " 12) Consultar hash (MD5 / SHA1 / SHA256)"
        echo " 13) Recriptografar com nova senha (exige senha atual)"
        echo "  0) Sair"
        echo

        read -r -p "Selecione uma opção: " option
        echo

        case "$option" in
            1) new_extraction ;;
            2) run_john_menu ;;
            3) show_history ;;
            4) generate_reports ;;
            5) list_files ;;
            6) show_status ;;
            7) clear_history ;;
            8) generate_wordlist ;;
            9) list_wordlists ;;
            10) new_extraction_from_url ;;
            11) copy_last_hash_menu ;;
            12) lookup_hash_menu ;;
            13) reencrypt_menu ;;
            0)
                success "Encerrando o Extrator PRO."
                exit 0
                ;;
            *)
                error "Opção inválida."
                sleep 1
                ;;
        esac
    done
}

# ---------- Entrada por argumentos ----------
usage() {
    cat <<EOF
Uso:
  $0                 Modo interativo
  $0 --help          Exibe esta ajuda
  $0 --version       Exibe a versão

O modo interativo oferece:
  - Detecção automática de PDF, ZIP, RAR e 7-Zip
  - Extração de hash de arquivo local
  - Extração de hash a partir de um link direto (http/https)
  - Copiar hash extraído para a área de transferência
  - Consulta de MD5 / SHA1 / SHA256 (base pública + John local)
  - Execução opcional do John the Ripper
  - Recriptografia com nova senha (exige a senha atual conhecida)
  - Geração de wordlists personalizadas com Crunch
  - Seleção de wordlist (padrão, geradas ou caminho manual)
  - Histórico CSV
  - Relatórios TXT e HTML
  - Diagnóstico do ambiente

Recriptografia (opção 13):
  - PDF  → requer qpdf
  - ZIP  → requer 7z (recomendado) ou unzip+zip
  - 7z   → requer 7z (p7zip-full)
  - RAR  → requer rar (CLI do WinRAR)
  - Sempre gera um NOVO arquivo; o original não é alterado.
  - A senha atual é obrigatória (pode usar a recuperada pelo John).

Use somente em arquivos próprios ou com autorização.
Não utilize para atacar sites, logins ou sistemas de terceiros.
EOF
}

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --version|-v) echo "$APP_NAME $VERSION"; exit 0 ;;
    "") init_dirs; menu ;;
    *) error "Argumento desconhecido: $1"; usage; exit 1 ;;
esac
