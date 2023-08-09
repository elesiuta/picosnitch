Name:           picosnitch
Version:        0.14.0
Release:        2%{?dist}
License:        GPL-3.0
Summary:        Monitor network traffic per executable using BPF
Url:            https://github.com/elesiuta/picosnitch
Source:         https://github.com/elesiuta/picosnitch/releases/download/v%{version}/picosnitch.tar.gz
BuildRequires:  python3
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-psutil
Requires:       python3
Requires:       python3-psutil
Requires:       python3-requests
Requires:       python3-pandas
Requires:       python3-geoip2
Suggests:       python3-plotly
Suggests:       pipx

%if 0%{?fedora}%{?mageia}
BuildRequires:  python3-wheel
Requires:       python3-dbus
%endif

%if 0%{?suse_version}
BuildRequires:  python3-wheel
BuildRequires:  python3-curses
Requires:       python3-curses
Requires:       python3-dash
Requires:       python3-dbus-python
Requires:       bcc-tools
%else
Requires:       bcc
%endif

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
%py3_build

%install
%py3_install
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
%{python3_sitelib}/picosnitch-*.egg-info/
%{python3_sitelib}/picosnitch.py
/usr/bin/picosnitch
%{_unitdir}/%{name}.service
%if 0%{?fedora}%{?suse_version}%{?mageia}
%{python3_sitelib}/__pycache__/picosnitch.cpython-*.pyc
%endif

%changelog
* Wed Aug 9 2023 Eric Lesiuta <elesiuta@gmail.com> - 0.14.0-2
- see releases on github for changes

