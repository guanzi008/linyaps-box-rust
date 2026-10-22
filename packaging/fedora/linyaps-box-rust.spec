%global debug_package %{nil}
%global _build_id_links none

Name:           linyaps-box-rust
Version:        2.4.0
Release:        1.rust1%{?dist}
Summary:        Rust OCI runtime for Linyaps applications
License:        LGPL-3.0-or-later AND Apache-2.0
URL:            https://github.com/guanzi008/linyaps-box-rust
Source0:        %{name}-%{version}.tar.xz
ExclusiveArch:  x86_64
BuildRequires:  cargo
BuildRequires:  rust >= 1.88
BuildRequires:  gcc
Provides:       linyaps-box = %{version}-%{release}
Conflicts:      linyaps-box
Conflicts:      linglong-box

%description
Command-compatible Rust implementation of the Linyaps OCI runtime, using
the bundled Youki libcontainer implementation. This is a third-party
build, not an official Fedora package.

%prep
%autosetup -p1

%build
export RUSTFLAGS="${RUSTFLAGS:-} -Cdebuginfo=0 -Cstrip=symbols"
cargo build --release --locked --offline

%install
install -Dm755 "${CARGO_TARGET_DIR:-target}/release/ll-box" "%{buildroot}%{_bindir}/ll-box"
install -Dm644 debian/ll-box.1 "%{buildroot}%{_mandir}/man1/ll-box.1"

%check
export RUSTFLAGS="${RUSTFLAGS:-} -Cdebuginfo=0 -Cstrip=symbols"
cargo test --release --locked --offline --all-targets
"${CARGO_TARGET_DIR:-target}/release/ll-box" --version

%files
%license LICENSE LICENSES
%doc README.md COMPATIBILITY.md
%{_bindir}/ll-box
%{_mandir}/man1/ll-box.1*

%changelog
* Thu Oct 22 2026 guanzi008 <20619190+guanzi008@users.noreply.github.com> - 2.4.0-1.rust1
- Add an offline-rebuildable Fedora RPM.
