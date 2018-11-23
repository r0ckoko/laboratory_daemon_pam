%define service_user knocker
%define protoname knock-knock
Name: knocker
Version: 0.1
Release: 1%{?dist}
Summary: authentication daemon
License: MIT
Group: System Enviroments/Daemons
Source0: %{name}-%{version}.tar.gz
Source1: %{name}
Source2: %{protoname}
Source3: %{name}.conf

BuildRoot:%{_tmppath}/%{name}-%{version}

BuildRequires: glibc make

%description
Authentication daemon provides authentication with password by using model
"Client-Server" based on Unix sockets

%package dev
Summary: Headers of authentication protocol KNOCK-KNOCK
Group: Development/Headers
%description dev
Header files of authentication protocol required for delopment of client
part

%package client
Summary: client library using KNOCK-KNOCK protocol
Group: Development/Library
Requires: %{name} = %{version}
Requires: %{name}-dev = %{version}
%description client
Demo client for demonstrate authentication based on KNOCK-KNOCK protocol

%prep
%setup -q -a0

%build
echo %{name}
make PREFIX=/usr NAME=%{name} %{?_smp_mflags}

%pre
if [ $(grep -c "%{service_user}" %{_sysconfdir}/passwd) = 0 ]
then
	useradd -r %{service_user}
else
	userdel %{service_user}
	useradd -r %{service_user}
fi

%install
rm -rf %{buildroot}
install -d %{buildroot}/%{_sysconfdir}/init.d
make PREFIX=/usr DESTDIR=%{buildroot} NAME=%{name} install
install -m 0644 %{SOURCE1} %{buildroot}/%{_sysconfdir}/init.d
install -d %{buildroot}/%{_sysconfdir}/pam.d
install -m 0644 %{SOURCE2} %{buildroot}/%{_sysconfdir}/pam.d
install -m 0644 %{SOURCE3} %{buildroot}/%{_sysconfdir}/
#for package dev
install -d %{buildroot}/%{_includedir}/%{protoname}
cp include/protocol.h %{buildroot}/%{_includedir}/%{protoname}

%post
chkconfig --add %{name}
chkconfig %{name} on 
service %{name} start

%preun
service %{name} stop

%postun
rm -rf %{_localstatedir}/run/%{name}
if [ $(grep -c "%{system_user}" %{_sysconfdir}/passwd) != 0 ]
then
	userdel %{service_user}
fi

%postun dev
rm -rf %{_includedir}/%{protoname}

%postun client
rm -f  %{_libdir}/lib%{name}.so

%clean
rm -rf %{buildroot}

%files
%attr(755,root,root) %{_bindir}/%{name}
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%attr(644,root,root) %{_sysconfdir}/pam.d/%{protoname}
%attr(644,root,root) %{_sysconfdir}/%{name}.conf

%files dev
%attr(644,root,root) %{_includedir}/%{protoname}/protocol.h

%files client
%attr(644,root,root) %{_libdir}/lib%{name}.so
