#!/bin/sh
# install.sh: download, verify and install ssh-1password from a GitHub Release (macOS, Linux).
#
#   sh install.sh                       latest release into ~/.local
#   sh install.sh --version 0.1.0       a given release
#   sh install.sh --prefix /opt/tools   files in <prefix>/share/ssh-1password, link in <prefix>/bin
#   sh install.sh --from <tarball>      install a local release tarball (no download, no checksum)
#   sh install.sh --uninstall           remove the link and the installed versions
#
# It only writes under <prefix>. It never runs `ssh-1password sync`, which writes under ~/.ssh:
# run that yourself afterwards.
set -eu

REPO="farming-apps/ssh-1password"
BASE_URL="https://github.com/$REPO/releases"

prefix="$HOME/.local"
version=""
from=""
uninstall=0

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; version="${2#v}"; shift 2 ;;
        --version=*) version="${1#*=}"; version="${version#v}"; shift ;;
        --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; prefix="$2"; shift 2 ;;
        --prefix=*) prefix="${1#*=}"; shift ;;
        --from) [ $# -ge 2 ] || die "--from needs a value"; from="$2"; shift 2 ;;
        --from=*) from="${1#*=}"; shift ;;
        --uninstall) uninstall=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

[ -n "$prefix" ] || die "--prefix is empty"
share_dir="$prefix/share/ssh-1password"
bin_dir="$prefix/bin"
link="$bin_dir/ssh-1password"

# --- uninstall ---------------------------------------------------------------------------------

if [ "$uninstall" = 1 ]; then
    if [ -L "$link" ]; then
        case "$(readlink "$link")" in
            "$share_dir"/*) rm -f "$link"; say "removed $link" ;;
            *) say "left $link alone: it does not point into $share_dir" ;;
        esac
    fi
    if [ -d "$share_dir" ]; then
        rm -rf "$share_dir"
        say "removed $share_dir"
    fi
    say "ssh-1password uninstalled. ~/.ssh, ~/.config/ssh-1password and your git config were not touched."
    exit 0
fi

# --- requirements ------------------------------------------------------------------------------

case "$(uname -s)" in
    Darwin|Linux) ;;
    *) die "unsupported system $(uname -s): ssh-1password runs on macOS and Linux" ;;
esac
command -v python3 >/dev/null 2>&1 || die "python3 not found (3.8 or newer is required)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' \
    || die "python3 $(python3 -c 'import platform; print(platform.python_version())') is too old: 3.8 or newer is required"
command -v tar >/dev/null 2>&1 || die "tar not found"

fetch() {  # fetch <url> <file>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
    else
        die "neither curl nor wget found"
    fi
}

sha256() {  # sha256 <file>  -> hex digest
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "neither sha256sum nor shasum found"
    fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# --- get the tarball ---------------------------------------------------------------------------

if [ -n "$from" ]; then
    [ -f "$from" ] || die "$from not found"
    tarball="$from"
    say "using local tarball $from (no checksum verification)"
else
    if [ -n "$version" ]; then
        url="$BASE_URL/download/v$version"
    else
        url="$BASE_URL/latest/download"
    fi
    say "downloading SHA256SUMS from $url"
    fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $url/SHA256SUMS (does the release exist?)"
    name="$(sed -n 's/^[0-9a-f]\{64\}  *\(ssh-1password-[0-9][^ /]*\.tar\.gz\)$/\1/p' "$tmp/SHA256SUMS" | head -n 1)"
    [ -n "$name" ] || die "SHA256SUMS lists no ssh-1password tarball"
    expected="$(grep "  *$name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
    say "downloading $name"
    fetch "$url/$name" "$tmp/$name" || die "could not download $url/$name"
    actual="$(sha256 "$tmp/$name")"
    [ "$actual" = "$expected" ] || die "checksum mismatch for $name: expected $expected, got $actual"
    say "checksum ok"
    tarball="$tmp/$name"
fi

# --- unpack ------------------------------------------------------------------------------------

top="$(tar tzf "$tarball" | head -n 1)"
top="${top%%/*}"
case "$top" in
    ssh-1password-[0-9]*) ;;
    *) die "$tarball does not look like an ssh-1password release (top directory: $top)" ;;
esac
ver="${top#ssh-1password-}"
mkdir -p "$tmp/x"
tar xzf "$tarball" -C "$tmp/x"
[ -f "$tmp/x/$top/ssh-1password.py" ] && [ -f "$tmp/x/$top/templates/hosts.yml" ] \
    || die "$tarball is missing ssh-1password.py or templates/hosts.yml"

# --- install -----------------------------------------------------------------------------------

if [ -e "$link" ] && [ ! -L "$link" ]; then
    die "$link exists and is not a symlink: move it away and re-run"
fi
dest="$share_dir/$ver"
mkdir -p "$share_dir" "$bin_dir"
if [ -d "$dest" ]; then
    rm -rf "$dest"
fi
mv "$tmp/x/$top" "$dest"
chmod 755 "$dest/ssh-1password.py"
ln -sfn "$dest/ssh-1password.py" "$link"
say "installed ssh-1password $ver: $link -> $dest/ssh-1password.py"

# keep only the version just installed
for old in "$share_dir"/*; do
    [ "$old" = "$dest" ] || [ ! -d "$old" ] || { rm -rf "$old"; say "removed old version $(basename "$old")"; }
done

"$link" --version >/dev/null || die "$link --version failed"

# --- next steps --------------------------------------------------------------------------------

case ":$PATH:" in
    *":$bin_dir:"*) cmd="ssh-1password" ;;
    *)
        cmd="$link"
        say ""
        say "$bin_dir is not in your PATH. Add this line to your shell profile (~/.zshrc or ~/.bashrc):"
        say "  export PATH=\"$bin_dir:\$PATH\""
        ;;
esac
say ""
say "Next, in a terminal (it writes under ~/.ssh):"
say "  $cmd sync      # creates ~/.config/ssh-1password/hosts.yml on the first run"
say "  \$EDITOR ~/.config/ssh-1password/hosts.yml"
say "  $cmd sync"
say "  $cmd doctor"
