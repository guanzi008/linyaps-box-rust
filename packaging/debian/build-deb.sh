#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$project_root"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'required command not found: %s\n' "$1" >&2
        exit 1
    }
}

detect_architecture() {
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --print-architecture
        return
    fi

    case "$(uname -m)" in
        x86_64) printf '%s\n' amd64 ;;
        aarch64) printf '%s\n' arm64 ;;
        riscv64) printf '%s\n' riscv64 ;;
        loongarch64) printf '%s\n' loong64 ;;
        *)
            printf 'unsupported Debian architecture for %s\n' "$(uname -m)" >&2
            exit 1
            ;;
    esac
}

package_version=$(awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^version = / {
        gsub(/^version = "/, "")
        gsub(/"$/, "")
        print
        exit
    }
' "$project_root/Cargo.toml")

if [[ -z "$package_version" ]]; then
    printf 'failed to read package version from Cargo.toml\n' >&2
    exit 1
fi

deb_version=${DEB_VERSION:-${package_version}~rust1-1}
deb_arch=${DEB_ARCH:-$(detect_architecture)}
native_arch=$(detect_architecture)
output_dir=${OUTPUT_DIR:-$project_root/dist}
maintainer=${DEB_MAINTAINER:-guanzi008 <20619190+guanzi008@users.noreply.github.com>}
source_date_epoch=${SOURCE_DATE_EPOCH:-}

if [[ -z "$source_date_epoch" ]]; then
    require_command git
    source_date_epoch=$(git log -1 --format=%ct)
fi

export SOURCE_DATE_EPOCH=$source_date_epoch

if [[ "$deb_arch" != "$native_arch" && ${LINYAPS_DEB_ALLOW_CROSS:-0} != 1 ]]; then
    printf 'DEB_ARCH=%s does not match native architecture %s\n' "$deb_arch" "$native_arch" >&2
    exit 1
fi

for command in cargo dpkg dpkg-deb dpkg-shlibdeps readelf md5sum gzip; do
    require_command "$command"
done

dpkg --validate-version "$deb_version"

if [[ ${CARGO_TARGET_DIR:-} = /* ]]; then
    target_dir=$CARGO_TARGET_DIR
elif [[ -n ${CARGO_TARGET_DIR:-} ]]; then
    target_dir=$project_root/$CARGO_TARGET_DIR
else
    target_dir=$project_root/target
fi

if [[ ${LINYAPS_DEB_SKIP_BUILD:-0} != 1 ]]; then
    cargo build --manifest-path "$project_root/Cargo.toml" --release --locked
fi

binary=$target_dir/release/ll-box
if [[ ! -x "$binary" ]]; then
    printf 'release binary not found: %s\n' "$binary" >&2
    exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/linyaps-box-deb.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

package_root=$work_dir/linglong-box
install -Dm755 "$binary" "$package_root/usr/bin/ll-box"
mkdir -p "$package_root/usr/share/doc/linglong-box"
cat >"$package_root/usr/share/doc/linglong-box/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: linyaps-box-rust
Source: https://github.com/guanzi008/linyaps-box-rust

Files: *
Copyright: 2022-2026 UnionTech Software Technology Co., Ltd.
           2026 linyaps-box-rust contributors
License: LGPL-3.0-or-later
 On Debian systems, the complete text of the GNU Lesser General Public
 License version 3 can be found in /usr/share/common-licenses/LGPL-3.

Files: vendor/libcontainer/*
Copyright: Youki contributors
License: Apache-2.0
 On Debian systems, the complete text of the Apache License version 2.0
 can be found in /usr/share/common-licenses/Apache-2.0.
EOF
cp -a "$project_root/LICENSES" "$package_root/usr/share/doc/linglong-box/licenses"

changelog_date=$(date -u --date="@$source_date_epoch" --rfc-email)
cat >"$work_dir/changelog.Debian" <<EOF
linglong-box ($deb_version) unstable; urgency=medium

  * Publish the complete Rust rewrite of the Linyaps OCI runtime.

 -- $maintainer  $changelog_date
EOF
gzip -n -9 -c "$work_dir/changelog.Debian" \
    >"$package_root/usr/share/doc/linglong-box/changelog.Debian.gz"

scan_dir=$work_dir/shlibdeps
mkdir -p "$scan_dir/debian"
cat >"$scan_dir/debian/control" <<EOF
Source: linglong-box
Section: admin
Priority: optional
Maintainer: $maintainer
Standards-Version: 4.6.2

Package: linglong-box
Architecture: any
Description: dependency scan package
EOF

shlib_arguments=()
while IFS= read -r -d '' executable; do
    if readelf -h "$executable" >/dev/null 2>&1 \
        && readelf -d "$executable" 2>/dev/null | grep -q '(NEEDED)'; then
        shlib_arguments+=("-e$executable")
    fi
done < <(find "$package_root" -type f -perm /111 -print0)

if ((${#shlib_arguments[@]} == 0)); then
    printf 'no dynamically linked executable found in package root\n' >&2
    exit 1
fi

shlib_output=$(cd "$scan_dir" && dpkg-shlibdeps --warnings=0 -O "${shlib_arguments[@]}")
shlib_depends=${shlib_output#shlibs:Depends=}

installed_size=$(du -sk "$package_root/usr" | awk '{ print $1 }')
mkdir -p "$package_root/DEBIAN"
cat >"$package_root/DEBIAN/control" <<EOF
Package: linglong-box
Version: $deb_version
Architecture: $deb_arch
Maintainer: $maintainer
Installed-Size: $installed_size
Depends: $shlib_depends
Section: admin
Priority: optional
Homepage: https://github.com/guanzi008/linyaps-box-rust
Description: Linyaps OCI runtime implemented in Rust
 A command-compatible Rust rewrite of the Linyaps OCI runtime.
EOF

(
    cd "$package_root"
    find . -path ./DEBIAN -prune -o -type f -print0 \
        | LC_ALL=C sort -z \
        | while IFS= read -r -d '' file; do md5sum "$file"; done \
        | sed 's#  \./#  #' >DEBIAN/md5sums
)

find "$package_root" -print0 \
    | xargs -0 touch --no-dereference --date="@$source_date_epoch"

mkdir -p "$output_dir"
artifact=$output_dir/linglong-box_${deb_version}_${deb_arch}.deb
dpkg-deb --root-owner-group --uniform-compression -Zxz -z9 \
    --build "$package_root" "$artifact"

(
    cd "$output_dir"
    sha256sum "$(basename "$artifact")" >SHA256SUMS
)

dpkg-deb --info "$artifact" >/dev/null
printf '%s\n' "$artifact"
