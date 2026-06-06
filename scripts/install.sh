#!/usr/bin/env sh
set -e

REPO="baidu/nettools"
BINDIR="${BINDIR:-}"
VERSION="${VERSION:-}"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { printf "${CYAN}info:${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}warn:${RESET} %s\n" "$1"; }
error() { printf "${RED}error:${RESET} %s\n" "$1" >&2; }

# ── Detect platform ──────────────────────────────────────────────────

detect_platform() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) error "Windows is not supported. Use WSL."; exit 1 ;;
        *)      error "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    printf "%s_%s" "$os" "$arch"
}

# ── Find latest release version ──────────────────────────────────────

get_latest_version() {
    if [ -n "$VERSION" ]; then
        # Strip leading 'v' if present
        printf "%s" "${VERSION#v}"
        return
    fi

    version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        2>/dev/null | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
        || true

    if [ -z "$version" ]; then
        error "Failed to determine latest version. Set VERSION manually."
        exit 1
    fi

    printf "%s" "$version"
}

# ── Find a writable install directory ────────────────────────────────

is_writable_dir() {
    [ -d "$1" ] && [ -w "$1" ]
}

ensure_in_path() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
    esac
    return 1
}

find_bindir() {
    # 1. User-specified via BINDIR
    if [ -n "$BINDIR" ]; then
        if is_writable_dir "$BINDIR"; then
            printf "%s" "$BINDIR"
            return
        fi
        error "BINDIR=$BINDIR is not writable. Aborting."
        exit 1
    fi

    # 2. Try common paths in order
    for dir in \
        /usr/local/bin \
        /opt/homebrew/bin \
        "$HOME/.local/bin" \
        "$HOME/bin"
    do
        if is_writable_dir "$dir"; then
            printf "%s" "$dir"
            return
        fi
    done

    # 3. Try creating ~/.local/bin
    mkdir -p "$HOME/.local/bin" 2>/dev/null && is_writable_dir "$HOME/.local/bin" && {
        printf "%s" "$HOME/.local/bin"
        return
    }

    error "No writable install directory found. Try: BINDIR=/path/to/dir $0"
    error "Or create ~/.local/bin and add it to your PATH."
    exit 1
}

# ── Download and install ─────────────────────────────────────────────

install() {
    platform=$(detect_platform)
    version=$(get_latest_version)
    bindir=$(find_bindir)

    archive="nettools_${version}_${platform}.tar.gz"
    url="https://github.com/${REPO}/releases/download/v${version}/${archive}"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading nettools v${version} for ${platform}..."

    if ! curl -fSL -o "${tmpdir}/${archive}" "$url"; then
        error "Download failed."
        error "URL: ${url}"
        error "The release for your platform may not exist yet."
        exit 1
    fi

    info "Extracting..."
    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"

    # Install all binaries found in the archive
    binaries=""
    installed=0
    for bin in bitflip bitflip6 baize lidar; do
        if [ -f "${tmpdir}/${bin}" ]; then
            install -m 755 "${tmpdir}/${bin}" "${bindir}/${bin}"
            binaries="${binaries}  ${bindir}/${bin}\n"
            installed=$((installed + 1))
        fi
    done

    if [ "$installed" -eq 0 ]; then
        error "No binaries found in the archive."
        exit 1
    fi

    # Summary
    printf "\n"
    printf "${GREEN}${BOLD}nettools v${version} installed successfully!${RESET}\n"
    printf "\n"
    printf "Installed ${installed} binaries to ${BOLD}${bindir}${RESET}:\n"
    printf "${binaries}"
    printf "\n"

    if ! ensure_in_path "$bindir"; then
        printf "${YELLOW}${BOLD}Note:${RESET} ${bindir} is not in your PATH.\n"
        printf "Add it by running:\n"
        printf "  echo 'export PATH=\"${bindir}:\$PATH\"' >> ~/.profile\n"
        printf "  source ~/.profile\n"
        printf "\n"
    fi

    # Print version of first installed binary to verify
    first_bin="bitflip"
    if [ -f "${bindir}/${first_bin}" ]; then
        installed_version=$("${bindir}/${first_bin}" --version 2>/dev/null || echo "(version info not available)")
        info "${first_bin} version: ${installed_version}"
    fi
}

install
