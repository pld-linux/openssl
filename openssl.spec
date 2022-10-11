#
# Conditional build:
%bcond_without	tests	# don't perform "make tests"
%bcond_without	zlib	# zlib: note - enables CVE-2012-4929 vulnerability
%bcond_with	sslv3	# SSLv3: note - enables CVE-2014-3566 vulnerability

Summary:	OpenSSL Toolkit libraries for the "Secure Sockets Layer" (SSL v2/v3)
Summary(de.UTF-8):	Secure Sockets Layer (SSL)-Kommunikationslibrary
Summary(es.UTF-8):	Biblioteca C que suministra algoritmos y protocolos criptográficos
Summary(fr.UTF-8):	Utilitaires de communication SSL (Secure Sockets Layer)
Summary(pl.UTF-8):	Biblioteki OpenSSL (SSL v2/v3)
Summary(pt_BR.UTF-8):	Uma biblioteca C que fornece vários algoritmos e protocolos criptográficos
Summary(ru.UTF-8):	Библиотеки и утилиты для соединений через Secure Sockets Layer
Summary(uk.UTF-8):	Бібліотеки та утиліти для з'єднань через Secure Sockets Layer
Name:		openssl
Version:	3.0.6
Release:	1
License:	Apache v2.0
Group:		Libraries
Source0:	https://www.openssl.org/source/%{name}-%{version}.tar.gz
# Source0-md5:	1ea2006ec913ef3de6894c1154d17d3e
Source2:	%{name}.1.pl
Source3:	%{name}-ssl-certificate.sh
Source4:	%{name}-c_rehash.sh
Patch0:		%{name}-optflags.patch
Patch1:		%{name}-ca-certificates.patch
Patch2:		%{name}-find.patch
Patch3:		pic.patch
Patch4:		engines-dir.patch
URL:		http://www.openssl.org/
%ifarch %{arm} ppc mips sparc sparcv9
BuildRequires:	libatomic-devel
%endif
BuildRequires:	libsctp-devel
BuildRequires:	linux-libc-headers >= 7:4.13
BuildRequires:	perl-devel >= 1:5.10.0
BuildRequires:	pkgconfig
BuildRequires:	rpm-perlprov >= 4.1-13
BuildRequires:	rpmbuild(macros) >= 1.745
BuildRequires:	sed >= 4.0
BuildRequires:	zlib-devel
Requires:	ca-certificates >= 20141019-3
Requires:	rpm-whiteout >= 1.7
Obsoletes:	SSLeay < 0.9.3
Obsoletes:	SSLeay-devel < 0.9.3
Obsoletes:	SSLeay-perl < 0.9.3
Obsoletes:	libopenssl0 < 1
Obsoletes:	openssl-engines < 3.0.0-2
%if "%{pld_release}" == "ac"
Conflicts:	neon < 0.26.3-3
Conflicts:	ntpd < 4.2.4p8-10
Conflicts:	openssh-clients < 2:5.8p1-9
Conflicts:	openssh-server < 2:5.8p1-9
%else
Conflicts:	neon < 0.29.6-8
Conflicts:	openssh-clients < 2:6.2p2-3
Conflicts:	openssh-server < 2:6.2p2-3
%endif
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
The OpenSSL Project is a collaborative effort to develop a robust,
commercial-grade, full-featured, and Open Source toolkit implementing
the Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS
v1) protocols with full-strength cryptography world-wide. The project
is managed by a worldwide community of volunteers that use the
Internet to communicate, plan, and develop the OpenSSL tookit and its
related documentation.

OpenSSL is based on the excellent SSLeay library developed by Eric A.
Young and Tim J. Hudson. The OpenSSL toolkit is licensed under an
Apache-style licence, which basically means that you are free to get
and use it for commercial and non-commercial purposes subject to some
simple license conditions.

This package contains shared libraries only, install openssl-tools if
you want to use openssl cmdline tool.

%description -l de.UTF-8
Openssl enthält das OpenSSL Zertifikatsmanagementtool und shared
libraries, die verschiedene Verschlüsselungs- und
Entschlüsselungsalgorithmen und -protokolle, wie DES, RC4, RSA und SSL
zur Verfügung stellen.

%description -l es.UTF-8
Biblioteca C que suministra algoritmos y protocolos criptográficos.

%description -l fr.UTF-8
OpenSSL est un outiil de gestion des certificats et les librairies
partagees qui fournit plusieurs protocoles et algorithmes de
codage/decodage, incluant DES, RC4, RSA et SSL.

%description -l pl.UTF-8
Implementacja protokołów kryptograficznych Secure Socket Layer (SSL)
v2/v3 oraz Transport Layer Security (TLS v1).

%description -l pt_BR.UTF-8
Uma biblioteca C que fornece vários algoritmos e protocolos
criptográficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas
compartilhadas e utilitários.

%description -l ru.UTF-8
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL.

%description -l uk.UTF-8
Програма openssl для роботи з сертифікатами та бібліотеки спільного
користування, що реалізують велику кількість криптографічних
алгоритмів, включаючи DES, RC4, RSA та SSL.

%package tools
Summary:	OpenSSL command line tool and utilities
Summary(pl.UTF-8):	Zestaw narzędzi i skryptów
Group:		Applications/Communications
Requires:	%{name} = %{version}-%{release}
Requires:	which

%description tools
The OpenSSL Toolkit cmdline tool openssl and utility scripts.

%description tools -l pl.UTF-8
Zestaw narzędzi i skryptów wywoływanych z linii poleceń.

%package tools-perl
Summary:	OpenSSL utilities written in Perl
Summary(pl.UTF-8):	Narzędzia OpenSSL napisane w perlu
Group:		Applications/Communications
Requires:	%{name} = %{version}-%{release}

%description tools-perl
OpenSSL Toolkit tools written in Perl.

%description tools-perl -l pl.UTF-8
Narzędzia OpenSSL napisane w perlu.

%package devel
Summary:	Development part of OpenSSL Toolkit libraries
Summary(de.UTF-8):	Secure Sockets Layer Kommunikationslibrary: statische libraries+header
Summary(es.UTF-8):	Bibliotecas y archivos de inclusión para desarrollo OpenSSL
Summary(fr.UTF-8):	Librairies statiques, headers et utilitaires pour communication SSL
Summary(pl.UTF-8):	Część bibiloteki OpenSSL przeznaczona dla programistów
Summary(pt_BR.UTF-8):	Bibliotecas e arquivos de inclusão para desenvolvimento OpenSSL
Summary(ru.UTF-8):	Библиотеки, хедеры и утилиты для Secure Sockets Layer
Summary(uk.UTF-8):	Бібліотеки, хедери та утиліти для Secure Sockets Layer
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
Obsoletes:	libopenssl0-devel < 1

%description devel
Development part of OpenSSL library.

%description devel -l es.UTF-8
Bibliotecas y archivos de inclusión para desarrollo OpenSSL

%description devel -l pl.UTF-8
Część biblioteki OpenSSL przeznaczona dla programistów.

%description devel -l pt_BR.UTF-8
Uma biblioteca C que fornece vários algoritmos e protocolos
criptográficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas e
arquivos de inclusão para desenvolvimento.

%description devel -l ru.UTF-8
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL. Включает библиотеки и хедеры для разработки приложений
с использованием SSL.

%description devel -l uk.UTF-8
Програма openssl для роботи з сертифікатами та бібліотеки спільного
користування, що реалізують велику кількість криптографічних
алгоритмів, включаючи DES, RC4, RSA та SSL. Містить бібліотеки та
хедери для розробки програм з використанням SSL.

%package static
Summary:	Static OpenSSL libraries
Summary(pl.UTF-8):	Statyczne wersje bibliotek z OpenSSL
Summary(pt_BR.UTF-8):	Bibliotecas estáticas para desenvolvimento com openssl
Summary(ru.UTF-8):	Статические библиотеки разработчика для OpenSSL
Summary(uk.UTF-8):	Статичні бібліотеки програміста для OpenSSL
Group:		Development/Libraries
Requires:	%{name}-devel = %{version}-%{release}

%description static
Static OpenSSL Toolkit libraries.

%description static -l pl.UTF-8
Statyczne wersje bibliotek z OpenSSL.

%description static -l pt_BR.UTF-8
Bibliotecas estáticas para desenvolvimento com openssl.

%description static -l ru.UTF-8
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL. Включает статические библиотеки для разработки
приложений с использованием OpenSSL.

%description static -l uk.UTF-8
Програма openssl для роботи з сертифікатами та бібліотеки спільного
користування, що реалізують велику кількість криптографічних
алгоритмів, включаючи DES, RC4, RSA та SSL. Містить статичні
бібліотеки для розробки програм з використанням SSL.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1

# fails with enable-sctp as of 1.1.1
%{__rm} test/recipes/80-test_ssl_new.t

%build
touch Makefile.*

PERL="%{__perl}" \
%{__perl} ./Configure \
	--prefix=%{_prefix} \
	--openssldir=%{_sysconfdir}/%{name} \
	--libdir=%{_lib} \
	-Wa,--noexecstack \
	shared \
	threads \
	%{?with_sslv3:enable-ssl3}%{!?with_sslv3:no-ssl3} \
	%{!?with_zlib:no-}zlib \
	enable-cms \
	enable-idea \
	enable-md2 \
	enable-mdc2 \
	enable-rc5 \
	enable-rfc3779 \
	enable-sctp \
	enable-seed \
	enable-camellia \
	enable-ktls \
	enable-fips \
%ifarch %{x8664}
	enable-ec_nistp_64_gcc_128 \
%endif
%ifarch %{ix86}
%ifarch i386
	386 linux-elf
# ^- allow running on 80386 (default code uses bswapl available on i486+)
%else
	linux-elf
%endif
%endif
%ifarch alpha
	linux-alpha-gcc
%endif
%ifarch %{x8664}
	linux-x86_64
%endif
%ifarch x32
	linux-x32
%endif
%ifarch ia64
	linux-ia64
%endif
%ifarch ppc
	linux-ppc
%endif
%ifarch ppc64
	linux-ppc64
%endif
%ifarch sparc
	linux-sparcv8
%endif
%ifarch sparcv9
	linux-sparcv9
%endif
%ifarch sparc64
	linux64-sparcv9
%endif
%ifarch %{arm}
	linux-armv4
%endif
%ifarch aarch64
	linux-aarch64
%endif

v=$(awk -F= '/^VERSION=/{print $2}' Makefile)
test "$v" = %{version}

%{__make} all \
	CC="%{__cc}" \
	OPTFLAGS="%{rpmcflags} %{rpmcppflags}" \
	INSTALLTOP=%{_prefix}

%if %{with tests}
%{__make} -j1 tests \
	CC="%{__cc}" \
	OPTFLAGS="%{rpmcflags} %{rpmcppflags}" \
	INSTALLTOP=%{_prefix}
%endif

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/%{name},%{_libdir}/%{name}} \
	$RPM_BUILD_ROOT{%{_mandir}/{pl/man1,man{1,3,5,7}},%{_datadir}/ssl} \
	$RPM_BUILD_ROOT%{_pkgconfigdir}

%{__make} install \
	CC="%{__cc}" \
	DESTDIR=$RPM_BUILD_ROOT

%{__mv} $RPM_BUILD_ROOT%{_libdir}/lib*.so.* $RPM_BUILD_ROOT/%{_lib}
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libcrypto.*) $RPM_BUILD_ROOT%{_libdir}/libcrypto.so
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libssl.*) $RPM_BUILD_ROOT%{_libdir}/libssl.so

%{__mv} $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/misc/* $RPM_BUILD_ROOT%{_libdir}/%{name}
%{__rm} -r $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/misc

# html version of man pages - not packaged
%{__rm} -r $RPM_BUILD_ROOT%{_docdir}/%{name}/html/man[1357]

cp -p %{SOURCE2} $RPM_BUILD_ROOT%{_mandir}/pl/man1/openssl.1
install -p %{SOURCE3} $RPM_BUILD_ROOT%{_bindir}/ssl-certificate
install -p %{SOURCE4} $RPM_BUILD_ROOT%{_bindir}/c_rehash.sh

%clean
rm -rf $RPM_BUILD_ROOT

%post   -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%triggerpostun -- %{name}-tools < 1.0.0-5
# the hashing format has changed in 1.0.0
[ ! -x %{_sbindir}/update-ca-certificates ] || %{_sbindir}/update-ca-certificates --fresh || :

%triggerpostun -- %{name} < 0.9.8i-2
# don't do anything on --downgrade
if [ $1 -le 1 ]; then
	exit 0
fi
if [ -d /var/lib/openssl/certs ] ; then
	mv /var/lib/openssl/certs/* %{_sysconfdir}/%{name}/certs 2>/dev/null || :
fi
if [ -d /var/lib/openssl/private ] ; then
	mv /var/lib/openssl/private/* %{_sysconfdir}/%{name}/private 2>/dev/null || :
fi
if [ -d /var/lib/openssl ] ; then
	for f in /var/lib/openssl/* ; do
		[ -f "$f" ] && mv "$f" %{_sysconfdir}/%{name} 2>/dev/null || :
	done
	rmdir /var/lib/openssl/* 2>/dev/null || :
	rmdir /var/lib/openssl 2>/dev/null || :
fi

%files
%defattr(644,root,root,755)
%doc CHANGES.md NEWS.md README.md doc/*.txt
%attr(755,root,root) /%{_lib}/libcrypto.so.*
%attr(755,root,root) /%{_lib}/libssl.so.*
%dir /%{_lib}/engines-3
%attr(755,root,root) /%{_lib}/engines-3/*.so
%dir /%{_lib}/ossl-modules
%attr(755,root,root) /%{_lib}/ossl-modules/fips.so
%attr(755,root,root) /%{_lib}/ossl-modules/legacy.so
%dir %{_sysconfdir}/%{name}
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/ct_log_list.cnf
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/fipsmodule.cnf
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/openssl.cnf
%dir %{_sysconfdir}/%{name}/certs
%dir %attr(700,root,root) %{_sysconfdir}/%{name}/private
%dir %{_datadir}/ssl
%{_mandir}/man5/config.5ossl*

%files tools
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/c_rehash.sh
%attr(755,root,root) %{_bindir}/openssl
%attr(754,root,root) %{_bindir}/ssl-certificate
%{_mandir}/man1/asn1parse.1ossl*
%{_mandir}/man1/ca.1ossl*
%{_mandir}/man1/ciphers.1ossl*
%{_mandir}/man1/cmp.1ossl*
%{_mandir}/man1/cms.1ossl*
%{_mandir}/man1/crl.1ossl*
%{_mandir}/man1/crl2pkcs7.1ossl*
%{_mandir}/man1/dgst.1ossl*
%{_mandir}/man1/dhparam.1ossl*
%{_mandir}/man1/dsa.1ossl*
%{_mandir}/man1/dsaparam.1ossl*
%{_mandir}/man1/ec.1ossl*
%{_mandir}/man1/ecparam.1ossl*
%{_mandir}/man1/enc.1ossl*
%{_mandir}/man1/engine.1ossl*
%{_mandir}/man1/errstr.1ossl*
%{_mandir}/man1/gendsa.1ossl*
%{_mandir}/man1/genpkey.1ossl*
%{_mandir}/man1/genrsa.1ossl*
%{_mandir}/man1/info.1ossl*
%{_mandir}/man1/kdf.1ossl*
%{_mandir}/man1/mac.1ossl*
%{_mandir}/man1/nseq.1ossl*
%{_mandir}/man1/ocsp.1ossl*
%{_mandir}/man1/openssl.1*
%{_mandir}/man1/openssl-*.1*
%{_mandir}/man1/passwd.1ossl*
%{_mandir}/man1/pkcs12.1ossl*
%{_mandir}/man1/pkcs7.1ossl*
%{_mandir}/man1/pkcs8.1ossl*
%{_mandir}/man1/pkey.1ossl*
%{_mandir}/man1/pkeyparam.1ossl*
%{_mandir}/man1/pkeyutl.1ossl*
%{_mandir}/man1/prime.1ossl*
%{_mandir}/man1/rand.1ossl*
%{_mandir}/man1/rehash.1ossl*
%{_mandir}/man1/req.1ossl*
%{_mandir}/man1/rsa.1ossl*
%{_mandir}/man1/rsautl.1ossl*
%{_mandir}/man1/s_client.1ossl*
%{_mandir}/man1/sess_id.1ossl*
%{_mandir}/man1/smime.1ossl*
%{_mandir}/man1/speed.1ossl*
%{_mandir}/man1/spkac.1ossl*
%{_mandir}/man1/srp.1ossl*
%{_mandir}/man1/s_server.1ossl*
%{_mandir}/man1/s_time.1ossl*
%{_mandir}/man1/storeutl.1ossl*
%{_mandir}/man1/ts.1ossl*
%{_mandir}/man1/verify.1ossl*
%{_mandir}/man1/version.1ossl*
%{_mandir}/man1/x509.1ossl*
%{_mandir}/man5/fips_config.5ossl*
%{_mandir}/man5/x509v3_config.5ossl*
%lang(pl) %{_mandir}/pl/man1/openssl.1*

%files tools-perl
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/c_rehash
%dir %{_libdir}/%{name}
%attr(755,root,root) %{_libdir}/%{name}/CA.pl
%attr(755,root,root) %{_libdir}/%{name}/tsget
%attr(755,root,root) %{_libdir}/%{name}/tsget.pl
%{_mandir}/man1/CA.pl.1ossl*
%{_mandir}/man1/c_rehash.1ossl*
%{_mandir}/man1/tsget.1ossl*

%files devel
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libcrypto.so
%attr(755,root,root) %{_libdir}/libssl.so
%{_includedir}/%{name}
%{_pkgconfigdir}/libcrypto.pc
%{_pkgconfigdir}/libssl.pc
%{_pkgconfigdir}/openssl.pc
%{_mandir}/man3/*.3ossl*
%{_mandir}/man7/*.7ossl*

%files static
%defattr(644,root,root,755)
%{_libdir}/libcrypto.a
%{_libdir}/libssl.a
