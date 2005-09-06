
%define name		tpm-tools
%define version		1.1.0
%define release		1

# RPM specfile for the trousers project

Name:		%{name}
Summary:	Management tools for the TPM hardware
Version:	%{version}
Release:	%{release}
License:	CPL
Group:		Productivity/Security
Source:		%{name}-%{version}.tar.gz
Url:		http://www.sf.net/projects/trousers
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Requires:	trousers

%description
tpm-tools is a group of tools to manage and utilize the Trusted Computing Group's
TPM hardware. TPM hardware can create, store and use RSA keys
securely (without ever being exposed in memory), verify a platform's software
state using cryptographic hashes and more.

%prep

%setup

%build
%configure --disable-pkcs11-support
make

%clean
[ "${RPM_BUILD_ROOT}" != "/" ] && [ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT};

%pre

%post
/sbin/ldconfig

%install
# This line keeps build machines from being affected
[ "${RPM_BUILD_ROOT}" != "/" ] && [ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT};
mkdir -p ${RPM_BUILD_ROOT}
make install DESTDIR=${RPM_BUILD_ROOT}

%postun
/sbin/ldconfig

# The files for the base package, 'tpm-tools'
%files
%doc LICENSE README
%attr(755, root, root) %{_bindir}/tpm_sealdata
%attr(755, root, root) %{_sbindir}/tpm_*
# Not built due to configure option of --disable-pkcs11-support
#%attr(755, root, root) %{_bindir}/tpmtoken_*
%{_libdir}/libtpm_unseal.a
%{_libdir}/libtpm_unseal.la
%{_libdir}/libtpm_unseal.so
%{_libdir}/libtpm_unseal.so.0.0.0
%{_mandir}/man1/*
%{_mandir}/man3/*
%{_mandir}/man8/*
%{_includedir}/tpm_tools/*.h
