Name:           picosnitch
Version:        1.0.3
Release:        1%{?dist}
License:        GPL-3.0-or-later
Summary:        Monitor network traffic per executable using BPF
Url:            https://github.com/elesiuta/picosnitch
Source:         https://github.com/elesiuta/picosnitch/releases/download/v%{version}/picosnitch.tar.gz
BuildRequires:  python3-devel >= 3.12
BuildRequires:  python3-hatchling
BuildRequires:  python3-pip
BuildRequires:  python3-wheel
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  bpftool
BuildRequires:  libbpf-devel
Requires:       python3 >= 3.12
Requires:       libbpf
Recommends:     libnotify
Suggests:       pipx

%if 0%{?fedora}
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-units
BuildRequires:  util-linux-core
%endif

%description
Monitors your bandwidth, breaking down traffic by executable, hash, parent, domain, port, or user over time

%global debug_package %{nil}

%prep
%setup -c -q -n %{name}

%build
%pyproject_wheel

%install
%pyproject_install
mkdir -vp %{buildroot}%{_unitdir}
install -D -m 644 debian/picosnitch.service %{buildroot}%{_unitdir}/%{name}.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files -n picosnitch
%license LICENSE
%doc README.md
%{python3_sitelib}/picosnitch/
%{python3_sitelib}/picosnitch-*.dist-info/
/usr/bin/picosnitch
%{_unitdir}/%{name}.service

%changelog
* Tue Jan 2 2024 Eric Lesiuta <elesiuta@gmail.com> - 1.0.3-1
- see releases on github for changes

