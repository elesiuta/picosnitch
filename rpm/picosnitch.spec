Name:           picosnitch
Version:        2.1.2
Release:        1%{?dist}
License:        GPL-3.0-or-later
Summary:        Monitor network traffic per executable using BPF
Url:            https://github.com/elesiuta/picosnitch
Source:         https://files.pythonhosted.org/packages/source/p/%{name}/%{name}-%{version}.tar.gz
BuildRequires:  python3-devel >= 3.12
BuildRequires:  python3-hatchling
BuildRequires:  python3-pip
BuildRequires:  python3-wheel
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  libbpf-devel
Requires:       python3 >= 3.12
Requires:       libbpf
Recommends:     libnotify

%if 0%{?fedora}
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-units
BuildRequires:  util-linux-core
%endif

%if 0%{?suse_version}
%define pythons python3
%endif

%description
Monitors your bandwidth, breaking down traffic by executable, hash, parent, domain, port, or user over time

%global debug_package %{nil}

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%if 0%{?fedora}
%pyproject_save_files picosnitch
%endif
mkdir -vp %{buildroot}%{_unitdir}
install -D -m 644 debian/picosnitch.service %{buildroot}%{_unitdir}/%{name}.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%if 0%{?fedora}
%files -n picosnitch -f %{pyproject_files}
%license LICENSE
%doc README.md
/usr/bin/picosnitch
%{_unitdir}/%{name}.service
%else
%files -n picosnitch
%license LICENSE
%doc README.md
%{python3_sitearch}/picosnitch/
%{python3_sitearch}/picosnitch-*.dist-info/
/usr/bin/picosnitch
%{_unitdir}/%{name}.service
%endif

%changelog
* Sat Jul 4 2026 Eric Lesiuta <elesiuta@gmail.com> - 2.1.2-1
- see releases on github for changes

