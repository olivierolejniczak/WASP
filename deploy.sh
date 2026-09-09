#!/usr/bin/env bash
# =============================================================================
# WASP — Web Application Security Probe
# Automated deployment script  |  v0.1
#
# COMPATIBILITY:
#   Distros:  Debian, Ubuntu, Kali, Parrot, Mint, Raspberry Pi OS
#             RHEL, CentOS, Fedora, Rocky, AlmaLinux, Amazon Linux
#             Arch Linux, Manjaro
#             Alpine Linux
#   Init:     systemd, OpenRC, SysV init, none (Docker / WSL2)
#   Arch:     x86_64, aarch64/arm64, armv7l (32-bit — Ollama excluded)
#   Shell:    bash 3.2+ (no bash 4+ features used)
#
# USAGE:
#   chmod +x deploy.sh && sudo ./deploy.sh
#   -- or run as root directly --
#
# ENVIRONMENT OVERRIDES (all optional):
#   WASP_DIR          install directory          (default: /opt/wasp)
#   OLLAMA_PORT       Ollama listen port          (default: 11435)
#   OLLAMA_HOST       Ollama listen address       (default: 0.0.0.0)
#   WASP_MODEL        Ollama model to pull        (default: auto-detected)
#   INSTALL_DOCKER    "yes"/"no"                  (default: yes if not present)
#   INSTALL_PD_TOOLS  "yes"/"no" httpx+nuclei    (default: yes)
#   JUICESHOP_PORT    Juice Shop port             (default: 3002)
#   OFFLINE           "yes" — skip all downloads  (default: no)
# =============================================================================

# ---------------------------------------------------------------------------
# Strict mode — but handle 'set -e' carefully with pipelines
# ---------------------------------------------------------------------------
set -uo pipefail
# NOT using 'set -e' globally — we use explicit error checks so pipelines
# and optional steps don't abort the whole script on non-fatal failures.

# ---------------------------------------------------------------------------
# Colour output — degrade gracefully if terminal has no colour support
# ---------------------------------------------------------------------------
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { printf '%s[*]%s %s\n'  "$CYAN"   "$RESET" "$*"; }
success() { printf '%s[+]%s %s\n'  "$GREEN"  "$RESET" "$*"; }
warn()    { printf '%s[!]%s %s\n'  "$YELLOW" "$RESET" "$*"; }
err()     { printf '%s[-]%s %s\n'  "$RED"    "$RESET" "$*" >&2; }
die()     { err "$*"; exit 1; }
section() { printf '\n%s=== %s ===%s\n' "$BOLD" "$*" "$RESET"; }
step()    { printf '  %s->%s %s\n' "$CYAN" "$RESET" "$*"; }

# ---------------------------------------------------------------------------
# Configuration — every value has a safe default; none are assumed
# ---------------------------------------------------------------------------
WASP_DIR="${WASP_DIR:-/opt/wasp}"
OLLAMA_PORT="${OLLAMA_PORT:-11435}"
OLLAMA_HOST_ADDR="${OLLAMA_HOST:-0.0.0.0}"
JUICESHOP_PORT="${JUICESHOP_PORT:-3002}"
INSTALL_DOCKER="${INSTALL_DOCKER:-yes}"
INSTALL_PD_TOOLS="${INSTALL_PD_TOOLS:-yes}"
OFFLINE="${OFFLINE:-no}"
WASP_MODEL="${WASP_MODEL:-}"         # empty = auto-detected below
LOG_FILE="/tmp/wasp-deploy-$$.log"

# Source directory: where this script lives
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Logging — everything goes to log file AND stdout
# ---------------------------------------------------------------------------
exec > >(tee -a "$LOG_FILE") 2>&1
info "Full log: $LOG_FILE"

# ---------------------------------------------------------------------------
# Helper: run a command, print it, capture failure without aborting
# ---------------------------------------------------------------------------
run() {
    step "$*"
    if ! "$@"; then
        warn "Command failed (non-fatal): $*"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Helper: require a command or die with a helpful message
# ---------------------------------------------------------------------------
require() {
    local cmd="$1" hint="${2:-}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die "Required command '$cmd' not found.${hint:+ $hint}"
    fi
}

# ---------------------------------------------------------------------------
# Helper: portable HTTP GET — tries curl then wget then python3
# ---------------------------------------------------------------------------
http_get() {
    # Usage: http_get URL [output_file]
    local url="$1" out="${2:-}"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$out" ]; then
            curl -fsSL --connect-timeout 15 --retry 3 "$url" -o "$out"
        else
            curl -fsSL --connect-timeout 15 --retry 3 "$url"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$out" ]; then
            wget -q --timeout=15 --tries=3 "$url" -O "$out"
        else
        wget -q --timeout=15 --tries=3 "$url" -O -
        fi
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import urllib.request, sys
url = sys.argv[1]; out = sys.argv[2] if len(sys.argv) > 2 else None
data = urllib.request.urlopen(url, timeout=15).read()
open(out,'wb').write(data) if out else sys.stdout.buffer.write(data)
" "$url" ${out:+"$out"}
    else
        die "No HTTP client found (need curl, wget, or python3)"
    fi
}

# ---------------------------------------------------------------------------
# Helper: portable JSON field extraction — no jq required
# ---------------------------------------------------------------------------
json_field() {
    # Usage: json_field "field_name" <<< "$json_string"
    # Works if python3 available, else falls back to grep/sed
    local field="$1"
    local input
    input=$(cat)
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('$field', ''))
except Exception:
    pass
" 2>/dev/null || true
    else
        # Crude fallback: grep for "field": "value"
        printf '%s' "$input" | grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | sed 's/.*:[[:space:]]*"\([^"]*\)".*/\1/' | head -1 || true
    fi
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
section "Pre-flight checks"

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        warn "Not root — re-running with sudo"
        exec sudo \
            WASP_DIR="$WASP_DIR" \
            OLLAMA_PORT="$OLLAMA_PORT" \
            OLLAMA_HOST="$OLLAMA_HOST_ADDR" \
            WASP_MODEL="$WASP_MODEL" \
            INSTALL_DOCKER="$INSTALL_DOCKER" \
            INSTALL_PD_TOOLS="$INSTALL_PD_TOOLS" \
            JUICESHOP_PORT="$JUICESHOP_PORT" \
            OFFLINE="$OFFLINE" \
            bash "$0" "$@"
    else
        die "Must run as root (sudo not found). Try: su -c 'bash $0'"
    fi
fi
success "Running as root"

# Bash version check — need at least 3.2
BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$BASH_MAJOR" -lt 3 ]; then
    die "bash 3.2+ required (found: $BASH_VERSION)"
fi
success "bash $BASH_VERSION"

# ---------------------------------------------------------------------------
# Detect OS and package manager — assume NOTHING
# ---------------------------------------------------------------------------
section "Detecting OS and package manager"

OS_ID="unknown"
OS_VER="unknown"
OS_NAME="unknown"
PKG_MGR="unknown"

# Read os-release safely — it may not exist, may use = or " syntax
if [ -f /etc/os-release ]; then
    OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
    OS_VER=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
elif [ -f /etc/debian_version ]; then
    OS_ID="debian"
    OS_VER=$(cat /etc/debian_version)
elif [ -f /etc/redhat-release ]; then
    OS_ID=$(awk '{print tolower($1)}' /etc/redhat-release)
    OS_VER=$(grep -o '[0-9.]*' /etc/redhat-release | head -1)
elif [ -f /etc/arch-release ]; then
    OS_ID="arch"
    OS_VER="rolling"
elif [ -f /etc/alpine-release ]; then
    OS_ID="alpine"
    OS_VER=$(cat /etc/alpine-release)
fi

info "OS: ${OS_NAME:-$OS_ID $OS_VER}"

# Detect package manager — in priority order, checking binary existence
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
else
    PKG_MGR="none"
    warn "No recognised package manager found — will skip system package installs"
fi
info "Package manager: $PKG_MGR"

# Detect init system — systemd, openrc, sysv, none
INIT_SYS="none"
if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
    # Extra check: systemctl may exist but be inactive (e.g. in containers)
    if systemctl is-system-running >/dev/null 2>&1 || \
       [ -d /run/systemd/system ]; then
        INIT_SYS="systemd"
    fi
fi
if [ "$INIT_SYS" = "none" ] && command -v rc-service >/dev/null 2>&1; then
    INIT_SYS="openrc"
fi
if [ "$INIT_SYS" = "none" ] && [ -f /etc/init.d/cron ] 2>/dev/null; then
    INIT_SYS="sysv"
fi
info "Init system: $INIT_SYS"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)    ARCH_NORM="x86_64";  PD_ARCH="amd64"  ;;
    aarch64|arm64)   ARCH_NORM="aarch64"; PD_ARCH="arm64"  ;;
    armv7l|armv6l)   ARCH_NORM="arm32";   PD_ARCH=""       ;;
    i386|i686)       ARCH_NORM="x86_32";  PD_ARCH=""       ;;
    *)               ARCH_NORM="$ARCH";   PD_ARCH=""       ;;
esac
info "Architecture: $ARCH ($ARCH_NORM)"

# Ollama only supports 64-bit
OLLAMA_SUPPORTED="yes"
if [ "$ARCH_NORM" = "arm32" ] || [ "$ARCH_NORM" = "x86_32" ]; then
    OLLAMA_SUPPORTED="no"
    warn "Ollama does not support 32-bit systems — LLM features will be disabled"
fi

# WSL detection — systemd may not manage services properly
IN_WSL="no"
if grep -qi microsoft /proc/version 2>/dev/null || \
   grep -qi wsl /proc/version 2>/dev/null; then
    IN_WSL="yes"
    warn "WSL detected — service management will use manual start instead of systemd"
fi

# Docker/container detection — some steps differ inside containers
IN_CONTAINER="no"
if [ -f /.dockerenv ] || \
   grep -q 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER="yes"
    warn "Container environment detected — skipping service installation steps"
fi

# ---------------------------------------------------------------------------
# Hardware detection — portable fallbacks for every tool
# ---------------------------------------------------------------------------
section "Detecting hardware"

# RAM — /proc/meminfo (Linux), sysctl (macOS/BSD), fallback to 1024
TOTAL_RAM_MB=1024
if [ -f /proc/meminfo ]; then
    _raw=$(grep '^MemTotal:' /proc/meminfo | awk '{print $2}' 2>/dev/null || true)
    [ -n "$_raw" ] && TOTAL_RAM_MB=$(( _raw / 1024 ))
elif command -v sysctl >/dev/null 2>&1; then
    _raw=$(sysctl -n hw.memsize 2>/dev/null || true)
    [ -n "$_raw" ] && TOTAL_RAM_MB=$(( _raw / 1024 / 1024 ))
fi
info "RAM: ${TOTAL_RAM_MB} MB"

# CPU cores — nproc, sysctl, /proc/cpuinfo, final fallback to 2
CPU_CORES=2
if command -v nproc >/dev/null 2>&1; then
    _c=$(nproc 2>/dev/null || true)
    [ -n "$_c" ] && CPU_CORES=$_c
elif command -v sysctl >/dev/null 2>&1; then
    _c=$(sysctl -n hw.ncpu 2>/dev/null || true)
    [ -n "$_c" ] && CPU_CORES=$_c
elif [ -f /proc/cpuinfo ]; then
    _c=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || true)
    [ -n "$_c" ] && CPU_CORES=$_c
fi
info "CPU cores: $CPU_CORES"

# Pick model based on hardware — only if not overridden by env var
if [ -z "$WASP_MODEL" ]; then
    if [ "$OLLAMA_SUPPORTED" = "no" ]; then
        WASP_MODEL=""
        warn "No model selected — Ollama not supported on this architecture"
    elif [ "$TOTAL_RAM_MB" -ge 16000 ]; then
        WASP_MODEL="qwen3:1.7b"
        info "Model: qwen3:1.7b  (16 GB+ RAM — best reasoning in sub-2B class)"
    elif [ "$TOTAL_RAM_MB" -ge 4000 ]; then
        WASP_MODEL="llama3.2:3b"
        info "Model: llama3.2:3b  (4–16 GB RAM — fast, reliable tool-calling)"
    else
        WASP_MODEL="llama3.2:1b"
        info "Model: llama3.2:1b  (< 4 GB RAM — minimal, limited capability)"
    fi
fi

# ---------------------------------------------------------------------------
# Offline mode check
# ---------------------------------------------------------------------------
if [ "$OFFLINE" = "yes" ]; then
    warn "OFFLINE=yes — skipping all downloads (apt, Ollama, PD tools, Docker)"
    warn "Assumes all system packages and Ollama are already installed"
fi

# ---------------------------------------------------------------------------
# Install system packages
# ---------------------------------------------------------------------------
section "Installing system packages"

# Per-package-manager install function — handles each distro's names
pkg_install() {
    # Usage: pkg_install <pkg_mgr> pkg1 pkg2 ...
    local mgr="$1"; shift
    case "$mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>/dev/null || warn "apt-get update failed (continuing)"
            apt-get install -y -q "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        dnf)
            dnf install -y -q "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        yum)
            yum install -y -q "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        pacman)
            pacman -Sy --noconfirm --quiet "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        apk)
            apk add --quiet "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        zypper)
            zypper install -y -q "$@" 2>/dev/null || warn "Some packages failed to install (continuing)"
            ;;
        none)
            warn "No package manager — skipping package install for: $*"
            ;;
    esac
}

# Package name maps per distro family — same logical package, different names
install_package() {
    # Usage: install_package <logical_name>
    local name="$1"
    local pkg=""
    case "$PKG_MGR" in
        apt)
            case "$name" in
                nmap)          pkg="nmap" ;;
                smbclient)     pkg="smbclient" ;;
                hydra)         pkg="hydra" ;;
                snmp)          pkg="snmp" ;;
                sqlmap)        pkg="sqlmap" ;;
                nikto)         pkg="nikto" ;;
                gobuster)      pkg="gobuster" ;;
                python3)       pkg="python3" ;;
                python3-venv)  pkg="python3-venv" ;;
                python3-pip)   pkg="python3-pip" ;;
                python3-dev)   pkg="python3-dev" ;;
                curl)          pkg="curl" ;;
                wget)          pkg="wget" ;;
                git)           pkg="git" ;;
                unzip)         pkg="unzip" ;;
                build-tools)   pkg="build-essential" ;;
                libssl)        pkg="libssl-dev" ;;
                libffi)        pkg="libffi-dev" ;;
                net-tools)     pkg="net-tools iputils-ping" ;;
                ca-certs)      pkg="ca-certificates" ;;
                *) pkg="$name" ;;
            esac ;;
        dnf|yum)
            case "$name" in
                nmap)          pkg="nmap" ;;
                smbclient)     pkg="samba-client" ;;
                hydra)         pkg="hydra" ;;
                snmp)          pkg="net-snmp-utils" ;;
                sqlmap)        pkg="sqlmap" ;;
                nikto)         pkg="nikto" ;;
                gobuster)      pkg="" ;;   # not in default RHEL repos
                python3)       pkg="python3" ;;
                python3-venv)  pkg="python3" ;;   # venv included in python3 on RHEL
                python3-pip)   pkg="python3-pip" ;;
                python3-dev)   pkg="python3-devel" ;;
                curl)          pkg="curl" ;;
                wget)          pkg="wget" ;;
                git)           pkg="git" ;;
                unzip)         pkg="unzip" ;;
                build-tools)   pkg="gcc make" ;;
                libssl)        pkg="openssl-devel" ;;
                libffi)        pkg="libffi-devel" ;;
                net-tools)     pkg="net-tools iputils" ;;
                ca-certs)      pkg="ca-certificates" ;;
                *) pkg="$name" ;;
            esac ;;
        pacman)
            case "$name" in
                nmap)          pkg="nmap" ;;
                smbclient)     pkg="smbclient" ;;
                hydra)         pkg="hydra" ;;
                snmp)          pkg="net-snmp" ;;
                sqlmap)        pkg="sqlmap" ;;
                nikto)         pkg="nikto" ;;
                gobuster)      pkg="gobuster" ;;
                python3)       pkg="python" ;;
                python3-venv)  pkg="" ;;   # built into python on Arch
                python3-pip)   pkg="python-pip" ;;
                python3-dev)   pkg="" ;;
                curl)          pkg="curl" ;;
                wget)          pkg="wget" ;;
                git)           pkg="git" ;;
                unzip)         pkg="unzip" ;;
                build-tools)   pkg="base-devel" ;;
                libssl)        pkg="openssl" ;;
                libffi)        pkg="libffi" ;;
                net-tools)     pkg="net-tools" ;;
                ca-certs)      pkg="ca-certificates" ;;
                *) pkg="$name" ;;
            esac ;;
        apk)
            case "$name" in
                nmap)          pkg="nmap" ;;
                smbclient)     pkg="samba-client" ;;
                hydra)         pkg="hydra" ;;
                snmp)          pkg="net-snmp-tools" ;;
                sqlmap)        pkg="sqlmap" ;;
                nikto)         pkg="" ;;   # not in Alpine main repos
                gobuster)      pkg="" ;;
                python3)       pkg="python3" ;;
                python3-venv)  pkg="python3" ;;
                python3-pip)   pkg="py3-pip" ;;
                python3-dev)   pkg="python3-dev" ;;
                curl)          pkg="curl" ;;
                wget)          pkg="wget" ;;
                git)           pkg="git" ;;
                unzip)         pkg="unzip" ;;
                build-tools)   pkg="build-base" ;;
                libssl)        pkg="openssl-dev" ;;
                libffi)        pkg="libffi-dev" ;;
                net-tools)     pkg="net-tools" ;;
                ca-certs)      pkg="ca-certificates" ;;
                *) pkg="$name" ;;
            esac ;;
        *)
            pkg="" ;;
    esac
    if [ -n "$pkg" ]; then
        # shellcheck disable=SC2086
        pkg_install "$PKG_MGR" $pkg
    fi
}

# List of logical packages to install
LOGICAL_PACKAGES="nmap smbclient hydra snmp sqlmap nikto gobuster \
    python3 python3-venv python3-pip python3-dev \
    curl wget git unzip build-tools libssl libffi net-tools ca-certs"

if [ "$OFFLINE" = "no" ]; then
    for pkg in $LOGICAL_PACKAGES; do
        install_package "$pkg"
    done
    success "System packages processed"
else
    info "OFFLINE mode — skipping system package install"
fi

# ---------------------------------------------------------------------------
# Verify Python 3 is available (critical dependency)
# ---------------------------------------------------------------------------
section "Checking Python 3"

PYTHON3=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        _ver=$("$candidate" --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+' | head -1)
        _major=$(printf '%s' "$_ver" | cut -d. -f1)
        _minor=$(printf '%s' "$_ver" | cut -d. -f2)
        if [ "${_major:-0}" -ge 3 ] && [ "${_minor:-0}" -ge 8 ]; then
            PYTHON3="$candidate"
            success "Python: $("$PYTHON3" --version)"
            break
        fi
    fi
done

[ -z "$PYTHON3" ] && die "Python 3.8+ not found and could not be installed. Install manually and re-run."

# Verify venv works — it's a separate package on some distros
VENV_OK="no"
if "$PYTHON3" -m venv --help >/dev/null 2>&1; then
    VENV_OK="yes"
else
    warn "python3-venv not working — attempting extra install"
    case "$PKG_MGR" in
        apt)    apt-get install -y -q python3-venv 2>/dev/null || true ;;
        dnf|yum) : ;;  # venv is part of python3 on RHEL
        pacman) : ;;   # same
        apk)    apk add --quiet python3 2>/dev/null || true ;;
    esac
    "$PYTHON3" -m venv --help >/dev/null 2>&1 && VENV_OK="yes" || true
fi
[ "$VENV_OK" = "no" ] && die "python3-venv is not working. Install python3-venv and re-run."

# Locate pip — prefer 'python3 -m pip' over standalone pip3 command
PIP3="$PYTHON3 -m pip"
"$PYTHON3" -m pip --version >/dev/null 2>&1 || \
    die "pip not available. Install python3-pip and re-run."

# ---------------------------------------------------------------------------
# Docker (optional)
# ---------------------------------------------------------------------------
if [ "$INSTALL_DOCKER" = "yes" ] && [ "$OFFLINE" = "no" ] && \
   [ "$IN_CONTAINER" = "no" ]; then
    section "Docker"
    if command -v docker >/dev/null 2>&1; then
        success "Docker already installed: $(docker --version 2>/dev/null || echo 'version unknown')"
    else
        info "Installing Docker…"
        case "$PKG_MGR" in
            apt)
                # Official Docker apt repo — full key + source list setup
                install_package ca-certs
                install_package curl
                TMP_KEY=$(mktemp)
                if http_get "https://download.docker.com/linux/${OS_ID}/gpg" "$TMP_KEY" 2>/dev/null; then
                    install -m 0644 "$TMP_KEY" /usr/share/keyrings/docker-archive-keyring.gpg
                    CODENAME=$(grep '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || \
                               lsb_release -cs 2>/dev/null || echo "bookworm")
                    printf 'deb [arch=%s signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/%s %s stable\n' \
                        "$(dpkg --print-architecture 2>/dev/null || echo amd64)" \
                        "$OS_ID" "$CODENAME" \
                        > /etc/apt/sources.list.d/docker.list
                    apt-get update -qq 2>/dev/null || true
                    apt-get install -y -q docker-ce docker-ce-cli containerd.io 2>/dev/null || \
                        warn "Docker CE install failed — trying docker.io fallback"
                    command -v docker >/dev/null 2>&1 || apt-get install -y -q docker.io 2>/dev/null || true
                else
                    warn "Docker GPG key download failed — trying install script fallback"
                    http_get "https://get.docker.com" | sh 2>/dev/null || warn "Docker install failed — skipping"
                fi
                rm -f "$TMP_KEY"
                ;;
            dnf|yum)
                "$PKG_MGR" install -y docker 2>/dev/null || \
                    http_get "https://get.docker.com" | sh 2>/dev/null || \
                    warn "Docker install failed — skipping"
                ;;
            pacman)
                pacman -Sy --noconfirm docker 2>/dev/null || warn "Docker install failed — skipping"
                ;;
            apk)
                apk add --quiet docker 2>/dev/null || warn "Docker install failed — skipping"
                ;;
            *)
                http_get "https://get.docker.com" | sh 2>/dev/null || warn "Docker install failed — skipping"
                ;;
        esac

        # Start Docker service
        if command -v docker >/dev/null 2>&1; then
            case "$INIT_SYS" in
                systemd)
                    systemctl enable docker 2>/dev/null || true
                    systemctl start  docker 2>/dev/null || true
                    ;;
                openrc)
                    rc-update add docker default 2>/dev/null || true
                    rc-service docker start 2>/dev/null || true
                    ;;
                sysv)
                    update-rc.d docker defaults 2>/dev/null || true
                    service docker start 2>/dev/null || true
                    ;;
                none)
                    dockerd &>/tmp/dockerd.log &
                    sleep 3
                    ;;
            esac

            # Add invoking user to docker group (if not root session itself)
            REAL_USER=""
            # SUDO_USER is set by sudo; check it exists and is non-root
            if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
                REAL_USER="$SUDO_USER"
            elif [ -n "${LOGNAME:-}" ] && [ "${LOGNAME}" != "root" ]; then
                REAL_USER="$LOGNAME"
            fi
            if [ -n "$REAL_USER" ]; then
                if getent group docker >/dev/null 2>&1; then
                    usermod -aG docker "$REAL_USER" 2>/dev/null && \
                        info "Added $REAL_USER to docker group (re-login to take effect)" || true
                fi
            fi
            success "Docker installed"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
if [ "$OLLAMA_SUPPORTED" = "yes" ] && [ "$IN_CONTAINER" = "no" ]; then
    section "Ollama (local AI inference)"

    OLLAMA_RUNNING="no"
    OLLAMA_API="http://localhost:${OLLAMA_PORT}"

    # Check if already running on our port
    if http_get "${OLLAMA_API}/api/tags" >/dev/null 2>&1; then
        OLLAMA_RUNNING="yes"
        success "Ollama already running on port ${OLLAMA_PORT}"
    fi

    if [ "$OLLAMA_RUNNING" = "no" ] && command -v ollama >/dev/null 2>&1; then
        # Ollama installed but not running on our port — configure and start
        info "Ollama found but not running — configuring port ${OLLAMA_PORT}"

        case "$INIT_SYS" in
            systemd)
                OVERRIDE_DIR="/etc/systemd/system/ollama.service.d"
                mkdir -p "$OVERRIDE_DIR"
                printf '[Service]\nEnvironment="OLLAMA_HOST=%s:%s"\n' \
                    "$OLLAMA_HOST_ADDR" "$OLLAMA_PORT" \
                    > "${OVERRIDE_DIR}/port.conf"
                systemctl daemon-reload 2>/dev/null || true
                systemctl enable ollama 2>/dev/null || true
                systemctl restart ollama 2>/dev/null || true
                sleep 5
                ;;
            openrc)
                printf '#!/sbin/openrc-run\ndescription="Ollama"\nexport OLLAMA_HOST=%s:%s\ncommand=/usr/local/bin/ollama\ncommand_args="serve"\npidfile=/run/ollama.pid\n' \
                    "$OLLAMA_HOST_ADDR" "$OLLAMA_PORT" \
                    > /etc/init.d/ollama
                chmod +x /etc/init.d/ollama
                rc-update add ollama default 2>/dev/null || true
                rc-service ollama restart 2>/dev/null || true
                sleep 5
                ;;
            *)
                # No init system — start manually in background
                OLLAMA_HOST="${OLLAMA_HOST_ADDR}:${OLLAMA_PORT}" nohup ollama serve \
                    >/tmp/ollama.log 2>&1 &
                info "Ollama started in background (log: /tmp/ollama.log)"
                sleep 5
                ;;
        esac

    elif [ "$OLLAMA_RUNNING" = "no" ] && [ "$OFFLINE" = "no" ]; then
        # Not installed at all — download and install
        info "Installing Ollama…"
        TMP_INSTALL=$(mktemp)
        if http_get "https://ollama.com/install.sh" "$TMP_INSTALL" 2>/dev/null; then
            OLLAMA_HOST="${OLLAMA_HOST_ADDR}:${OLLAMA_PORT}" bash "$TMP_INSTALL" || \
                warn "Ollama install script reported an error"
            rm -f "$TMP_INSTALL"

            # Set port via init system override
            case "$INIT_SYS" in
                systemd)
                    if systemctl list-unit-files ollama.service >/dev/null 2>&1; then
                        OVERRIDE_DIR="/etc/systemd/system/ollama.service.d"
                        mkdir -p "$OVERRIDE_DIR"
                        printf '[Service]\nEnvironment="OLLAMA_HOST=%s:%s"\n' \
                            "$OLLAMA_HOST_ADDR" "$OLLAMA_PORT" \
                            > "${OVERRIDE_DIR}/port.conf"
                        systemctl daemon-reload 2>/dev/null || true
                        systemctl enable ollama 2>/dev/null || true
                        systemctl start  ollama 2>/dev/null || true
                    else
                        # Installer didn't create a service unit — run manually
                        OLLAMA_HOST="${OLLAMA_HOST_ADDR}:${OLLAMA_PORT}" \
                            nohup ollama serve >/tmp/ollama.log 2>&1 &
                    fi
                    ;;
                openrc)
                    OLLAMA_HOST="${OLLAMA_HOST_ADDR}:${OLLAMA_PORT}" \
                        nohup ollama serve >/tmp/ollama.log 2>&1 &
                    ;;
                *)
                    OLLAMA_HOST="${OLLAMA_HOST_ADDR}:${OLLAMA_PORT}" \
                        nohup ollama serve >/tmp/ollama.log 2>&1 &
                    ;;
            esac

        else
            rm -f "$TMP_INSTALL"
            warn "Could not download Ollama install script — skipping"
            OLLAMA_SUPPORTED="no"
        fi
    fi

    # Wait for Ollama to be ready (up to 30s)
    if command -v ollama >/dev/null 2>&1; then
        info "Waiting for Ollama API on port ${OLLAMA_PORT}…"
        _waited=0
        while [ $_waited -lt 30 ]; do
            if http_get "${OLLAMA_API}/api/tags" >/dev/null 2>&1; then
                success "Ollama is ready on port ${OLLAMA_PORT}"
                OLLAMA_RUNNING="yes"
                break
            fi
            sleep 2
            _waited=$(( _waited + 2 ))
        done
        [ "$OLLAMA_RUNNING" = "no" ] && warn "Ollama API not responding after 30s — check manually"
    fi

    # ---------------------------------------------------------------------------
    # Pull AI model
    # ---------------------------------------------------------------------------
    if [ "$OLLAMA_RUNNING" = "yes" ] && [ -n "$WASP_MODEL" ] && \
       [ "$OFFLINE" = "no" ]; then
        section "Pulling AI model: $WASP_MODEL"

        # Check if model already present
        MODELS_JSON=$(http_get "${OLLAMA_API}/api/tags" 2>/dev/null || echo '{}')
        if printf '%s' "$MODELS_JSON" | grep -q "\"${WASP_MODEL}\""; then
            success "Model ${WASP_MODEL} already present"
        else
            info "Pulling ${WASP_MODEL} — this may take several minutes…"
            # Try ollama CLI first (shows progress), then fall back to API
            if command -v ollama >/dev/null 2>&1; then
                OLLAMA_HOST="localhost:${OLLAMA_PORT}" ollama pull "$WASP_MODEL" || \
                    warn "ollama pull failed — model may need to be pulled manually"
            else
                http_get "${OLLAMA_API}/api/pull" >/dev/null <<PULLEOF || true
{"name":"${WASP_MODEL}"}
PULLEOF
            fi
            success "Model pull initiated for ${WASP_MODEL}"
        fi
    fi

elif [ "$IN_CONTAINER" = "yes" ]; then
    warn "Container detected — skipping Ollama service install"
    warn "Mount Ollama socket or set OLLAMA_PORT to point at host Ollama"
fi

# ---------------------------------------------------------------------------
# ProjectDiscovery tools: httpx and nuclei
# ---------------------------------------------------------------------------
if [ "$INSTALL_PD_TOOLS" = "yes" ] && [ "$OFFLINE" = "no" ] && \
   [ -n "$PD_ARCH" ]; then
    section "ProjectDiscovery tools (httpx + nuclei)"

    install_pd_tool() {
        local tool="$1" repo="$2"
        local dest="/usr/local/bin/${tool}"
        if command -v "$tool" >/dev/null 2>&1; then
            success "$tool already installed"
            return 0
        fi
        info "Installing $tool from GitHub releases…"
        # Get latest version tag via API — fallback to hardcoded recent version
        VER=$(http_get "https://api.github.com/repos/projectdiscovery/${repo}/releases/latest" 2>/dev/null \
              | json_field "tag_name" || echo "")
        # Fallback versions if API unreachable
        [ -z "$VER" ] && case "$tool" in
            httpx)   VER="v1.6.10" ;;
            nuclei)  VER="v3.3.7"  ;;
        esac
        VER_NUM="${VER#v}"
        URL="https://github.com/projectdiscovery/${repo}/releases/download/${VER}/${tool}_${VER_NUM}_linux_${PD_ARCH}.zip"
        TMP_DIR=$(mktemp -d)
        if http_get "$URL" "${TMP_DIR}/${tool}.zip" 2>/dev/null; then
            if command -v unzip >/dev/null 2>&1; then
                unzip -q "${TMP_DIR}/${tool}.zip" -d "$TMP_DIR" 2>/dev/null || true
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c "
import zipfile, sys
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
" "${TMP_DIR}/${tool}.zip" "$TMP_DIR" 2>/dev/null || true
            fi
            if [ -f "${TMP_DIR}/${tool}" ]; then
                install -m 755 "${TMP_DIR}/${tool}" "$dest"
                success "$tool installed → $dest"
            else
                warn "$tool binary not found in zip — skipping"
            fi
        else
            warn "$tool download failed — skipping (WASP works without it)"
        fi
        rm -rf "$TMP_DIR"
    }

    install_pd_tool "httpx"  "httpx"
    install_pd_tool "nuclei" "nuclei"

    # Update nuclei templates if nuclei installed (fail silently)
    if command -v nuclei >/dev/null 2>&1; then
        nuclei -update-templates -silent >/dev/null 2>&1 &
        info "nuclei templates updating in background"
    fi
fi

# ---------------------------------------------------------------------------
# Install WASP source
# ---------------------------------------------------------------------------
section "Installing WASP to ${WASP_DIR}"

# Create install directory safely
mkdir -p "$WASP_DIR" || die "Cannot create ${WASP_DIR} — check permissions"

# Copy source files — prefer rsync but fall back to cp -r
info "Copying source files…"
if command -v rsync >/dev/null 2>&1; then
    rsync -a \
        --exclude='.venv' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        --exclude='wasp-*.md' \
        --exclude='wasp-network-*.md' \
        --exclude='deploy.sh' \
        "${SCRIPT_DIR}/" "${WASP_DIR}/"
else
    # Portable cp fallback — exclude with find+cp
    find "$SCRIPT_DIR" \
        -not -path '*/.venv/*' \
        -not -path '*/__pycache__/*' \
        -not -name '*.pyc' \
        -not -name '*.pyo' \
        -not -name 'wasp-*.md' \
        -not -name 'wasp-network-*.md' \
        -not -name 'deploy.sh' \
        | while IFS= read -r src; do
            rel="${src#$SCRIPT_DIR/}"
            dst="${WASP_DIR}/${rel}"
            if [ -d "$src" ]; then
                mkdir -p "$dst"
            else
                mkdir -p "$(dirname "$dst")"
                cp "$src" "$dst"
            fi
        done
fi

chmod +x "${WASP_DIR}/wasp.py"
success "Source copied to ${WASP_DIR}"

# ---------------------------------------------------------------------------
# Python virtual environment
# ---------------------------------------------------------------------------
section "Python virtual environment"

WASP_VENV="${WASP_DIR}/.venv"

# Remove broken venv if it exists
if [ -d "$WASP_VENV" ] && ! "${WASP_VENV}/bin/python" --version >/dev/null 2>&1; then
    warn "Existing venv appears broken — removing"
    rm -rf "$WASP_VENV"
fi

if [ ! -d "$WASP_VENV" ]; then
    info "Creating venv at ${WASP_VENV}…"
    "$PYTHON3" -m venv "$WASP_VENV" || die "venv creation failed"
fi

VENV_PY="${WASP_VENV}/bin/python"
VENV_PIP="${WASP_VENV}/bin/pip"

# Verify venv python works
"$VENV_PY" --version >/dev/null 2>&1 || die "venv python not working"
success "venv Python: $("$VENV_PY" --version)"

# Upgrade pip inside venv quietly
"$VENV_PIP" install -q --upgrade pip 2>/dev/null || \
    "$VENV_PY" -m pip install -q --upgrade pip 2>/dev/null || \
    warn "pip upgrade failed — continuing with existing pip"

# Install requirements
info "Installing Python requirements…"
if [ -f "${WASP_DIR}/requirements.txt" ]; then
    "$VENV_PIP" install -q -r "${WASP_DIR}/requirements.txt" || \
        die "pip install failed — check ${LOG_FILE} for details"
    success "Python requirements installed"
else
    die "requirements.txt not found in ${WASP_DIR}"
fi

# Install impacket for AD/Kerberos features
info "Installing impacket (AD attack tools)…"
"$VENV_PIP" install -q impacket 2>/dev/null && \
    success "impacket installed" || \
    warn "impacket install failed — AD/Kerberos features limited"

# Install bloodhound-python for AD attack-path collection (bloodhound_collect tool)
info "Installing bloodhound (AD attack-path collector)…"
"$VENV_PIP" install -q bloodhound 2>/dev/null && \
    success "bloodhound installed" || \
    warn "bloodhound install failed — bloodhound_collect tool unavailable"

# ---------------------------------------------------------------------------
# crackmapexec / netexec — network/AD scan support (wasp doctor checks for
# the binary name 'crackmapexec', but the project renamed to netexec and
# is no longer on PyPI — install netexec via pipx from git, then symlink)
# ---------------------------------------------------------------------------
if [ "$OFFLINE" = "no" ] && ! command -v crackmapexec >/dev/null 2>&1; then
    section "crackmapexec (netexec) — AD/network scan support"
    install_package pipx
    install_package build-tools
    if [ "$PKG_MGR" = "apt" ]; then
        pkg_install apt rustc cargo
    fi
    REAL_HOME="${HOME:-/root}"
    if command -v pipx >/dev/null 2>&1; then
        pipx install --quiet "git+https://github.com/Pennyw0rth/NetExec" 2>/dev/null && \
            success "netexec installed via pipx" || \
            warn "netexec install failed — crackmapexec/AD features unavailable"
        if [ -x "${REAL_HOME}/.local/bin/nxc" ]; then
            ln -sf "${REAL_HOME}/.local/bin/nxc" /usr/local/bin/crackmapexec
            success "crackmapexec → nxc symlinked"
        fi
    else
        warn "pipx not available — skipping netexec install"
    fi
fi

# ---------------------------------------------------------------------------
# Write config.yaml — tuned to this hardware
# ---------------------------------------------------------------------------
section "Writing config.yaml"

# Compute sensible limits — clamp to sane ranges
NMAP_RATE=$(( CPU_CORES * 200 ))
[ "$NMAP_RATE" -gt 2000 ] && NMAP_RATE=2000
[ "$NMAP_RATE" -lt 200  ] && NMAP_RATE=200

GOBUSTER_THREADS=$(( CPU_CORES * 2 ))
[ "$GOBUSTER_THREADS" -gt 40 ] && GOBUSTER_THREADS=40
[ "$GOBUSTER_THREADS" -lt 5  ] && GOBUSTER_THREADS=5

HTTPX_THREADS=$(( CPU_CORES * 2 ))
[ "$HTTPX_THREADS" -gt 20 ] && HTTPX_THREADS=20
[ "$HTTPX_THREADS" -lt 3  ] && HTTPX_THREADS=3

NUCLEI_RATE=$(( CPU_CORES * 5 ))
[ "$NUCLEI_RATE" -gt 50 ] && NUCLEI_RATE=50
[ "$NUCLEI_RATE" -lt 5  ] && NUCLEI_RATE=5

if [ "$TOTAL_RAM_MB" -ge 8000 ] && [ "$CPU_CORES" -ge 4 ]; then
    WALL_BUDGET=840; MAX_TOKENS=256; TOOL_TIMEOUT=45; RECON_TIMEOUT=90
else
    WALL_BUDGET=1200; MAX_TOKENS=128; TOOL_TIMEOUT=60; RECON_TIMEOUT=120
fi

MODEL_LINE="${WASP_MODEL:-llama3.2:3b}"

cat > "${WASP_DIR}/config.yaml" << CFGEOF
# WASP config — generated by deploy.sh
# Hardware: ${ARCH} | ${CPU_CORES} cores | ${TOTAL_RAM_MB} MB RAM | ${OS_ID} ${OS_VER}

orchestrator:
  provider:       "ollama"
  model:          "${MODEL_LINE}"
  endpoint:       "http://localhost:${OLLAMA_PORT}"
  temperature:    0.1
  max_tokens:     ${MAX_TOKENS}
  context_window: 8192

lite:
  wall_clock_budget_s: ${WALL_BUDGET}
  max_hypotheses:      6
  tool_timeout_s:      ${TOOL_TIMEOUT}
  recon_timeout_s:     ${RECON_TIMEOUT}
  result_truncate_chars: 2048
  wordlist: "${WASP_DIR}/wasp/wordlist.txt"

tools:
  nmap:
    rate: ${NMAP_RATE}
  httpx:
    follow_redirects: true
    timeout: 10
    threads: ${HTTPX_THREADS}
  gobuster:
    threads: ${GOBUSTER_THREADS}
  sqlmap:
    level: 1
    risk: 1
    technique: "B"
  nikto:
    max_time: 60
  nuclei:
    severity: ["critical", "high"]
    rate_limit: ${NUCLEI_RATE}

output:
  dir: "."
CFGEOF
success "config.yaml written"

# ---------------------------------------------------------------------------
# Create 'wasp' global command
# ---------------------------------------------------------------------------
section "Creating global 'wasp' command"

# Find a writable directory in PATH for the wrapper
WRAPPER_DIR=""
for candidate in /usr/local/bin /usr/bin "$HOME/.local/bin"; do
    if [ -d "$candidate" ] && [ -w "$candidate" ]; then
        WRAPPER_DIR="$candidate"
        break
    fi
done

# If ~/.local/bin doesn't exist but we need it, create it
if [ -z "$WRAPPER_DIR" ]; then
    mkdir -p "$HOME/.local/bin"
    WRAPPER_DIR="$HOME/.local/bin"
    warn "Using ${WRAPPER_DIR} — make sure it is in your PATH"
fi

cat > "${WRAPPER_DIR}/wasp" << WRAPEOF
#!/bin/sh
# WASP wrapper — generated by deploy.sh
exec "${VENV_PY}" "${WASP_DIR}/wasp.py" "\$@"
WRAPEOF
chmod +x "${WRAPPER_DIR}/wasp"
success "'wasp' command created at ${WRAPPER_DIR}/wasp"

# wasp-reports helper
cat > "${WRAPPER_DIR}/wasp-reports" << RPTEOF
#!/bin/sh
# List all WASP scan reports
find "${WASP_DIR}" /tmp /var/log \
    \( -name "wasp-*.md" -o -name "wasp-network-*.md" \) \
    -print 2>/dev/null | sort
RPTEOF
chmod +x "${WRAPPER_DIR}/wasp-reports"
success "'wasp-reports' command created"

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------
section "Verifying installation"

info "Running wasp doctor…"
cd "${WASP_DIR}"
"$VENV_PY" wasp.py doctor || warn "Doctor reported issues — see above (non-fatal)"

# Confirm wasp command works
if "${WRAPPER_DIR}/wasp" version >/dev/null 2>&1; then
    success "wasp command: OK ($(${WRAPPER_DIR}/wasp version))"
else
    warn "'wasp' command test failed — may need PATH update"
fi

# ---------------------------------------------------------------------------
# Optional: Juice Shop lab
# ---------------------------------------------------------------------------
section "OWASP Juice Shop (optional)"

if command -v docker >/dev/null 2>&1; then
    # Check Docker is actually responsive
    DOCKER_OK="no"
    docker info >/dev/null 2>&1 && DOCKER_OK="yes"

    if [ "$DOCKER_OK" = "yes" ]; then
        # Only prompt if stdin is a real terminal
        ANSWER="n"
        if [ -t 0 ]; then
            printf '  Start OWASP Juice Shop on port %s for immediate testing? [y/N] ' \
                "$JUICESHOP_PORT"
            read -r ANSWER || ANSWER="n"
        fi

        case "$ANSWER" in
            [Yy]|[Yy][Ee][Ss])
                info "Pulling Juice Shop image…"
                docker pull bkimminich/juice-shop:latest 2>/dev/null || \
                    warn "docker pull failed — image may already be cached"
                docker rm -f juice-shop 2>/dev/null || true
                docker run -d \
                    --name juice-shop \
                    --restart unless-stopped \
                    -p "${JUICESHOP_PORT}:3000" \
                    bkimminich/juice-shop:latest >/dev/null
                # Wait up to 30s
                _w=0
                while [ $_w -lt 30 ]; do
                    if http_get "http://localhost:${JUICESHOP_PORT}/" >/dev/null 2>&1; then
                        success "Juice Shop running → http://localhost:${JUICESHOP_PORT}"
                        break
                    fi
                    sleep 2; _w=$(( _w + 2 ))
                done
                [ $_w -ge 30 ] && warn "Juice Shop did not respond in 30s — check: docker logs juice-shop"
                ;;
            *)
                info "Skipping Juice Shop"
                ;;
        esac
    else
        warn "Docker not responding — skipping Juice Shop"
    fi
else
    info "Docker not installed — skipping Juice Shop (install Docker and run: docker run -d -p ${JUICESHOP_PORT}:3000 bkimminich/juice-shop)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Deployment complete"

cat << SUMEOF

  ${GREEN}${BOLD}WASP is ready.${RESET}

  Install dir  :  ${WASP_DIR}
  Config       :  ${WASP_DIR}/config.yaml
  Model        :  ${MODEL_LINE}  @ localhost:${OLLAMA_PORT}
  Command      :  ${WRAPPER_DIR}/wasp
  Log          :  ${LOG_FILE}

  ${BOLD}Quick start:${RESET}

    wasp scan http://TARGET                  # web app
    wasp scan 192.168.1.10                   # auto-detect (Windows/Linux/etc.)
    wasp scan 192.168.1.10 --type windows    # force type
    wasp network 192.168.1.0/24              # full network scan
    wasp scan http://localhost:${JUICESHOP_PORT}       # Juice Shop (if started)
    wasp doctor                              # check setup
    wasp-reports                             # list all reports

  ${BOLD}Upgrade model (better results):${RESET}
    OLLAMA_HOST=localhost:${OLLAMA_PORT} ollama pull qwen3:1.7b
    # edit ${WASP_DIR}/config.yaml  →  model: "qwen3:1.7b"

  ${BOLD}Service management:${RESET}
SUMEOF

case "$INIT_SYS" in
    systemd) printf '    systemctl status ollama     # Ollama service\n' ;;
    openrc)  printf '    rc-service ollama status    # Ollama service\n' ;;
    sysv)    printf '    service ollama status       # Ollama service\n' ;;
    none)    printf '    cat /tmp/ollama.log         # Ollama log\n' ;;
esac

printf '\n'

exit 0
