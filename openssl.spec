# TODO
# - consider dropping last optflags.patch hunk and return to SOMAJOR (.so.1) sonames
# - find a way to simplify (drop) openssl-optflags.patch, it's pain to update here in pld
#
# Conditional build:
%bcond_without	tests	# don't perform "make tests"
%bcond_without	zlib	# zlib: note - enables CVE-2012-4929 vulnerability
%bcond_without	sslv2	# SSLv2: note - many flaws http://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_2.0
%bcond_without	sslv3	# SSLv3: note - enables  CVE-2014-3566 vulnerability
%bcond_with	purify	# Compile openssl with "-DPURIFY", useful when one wants to
			# use valgrind debugger against openssl-linked programs
%bcond_with	snap	# use GitHub snapshot to build branch release

%define		subver	pre6
%define		rel		0.1
%include	/usr/lib/rpm/macros.perl
Summary:	OpenSSL Toolkit libraries for the "Secure Sockets Layer" (SSL v2/v3)
Summary(de.UTF-8):	Secure Sockets Layer (SSL)-Kommunikationslibrary
Summary(es.UTF-8):	Biblioteca C que suministra algoritmos y protocolos criptográficos
Summary(fr.UTF-8):	Utilitaires de communication SSL (Secure Sockets Layer)
Summary(pl.UTF-8):	Biblioteki OpenSSL (SSL v2/v3)
Summary(pt_BR.UTF-8):	Uma biblioteca C que fornece vários algoritmos e protocolos criptográficos
Summary(ru.UTF-8):	Библиотеки и утилиты для соединений через Secure Sockets Layer
Summary(uk.UTF-8):	Бібліотеки та утиліти для з'єднань через Secure Sockets Layer
Name:		openssl
# 1.0.2 will be LTS release
# Version 1.0.2 will be supported until 2019-12-31.
# https://www.openssl.org/about/releasestrat.html
Version:	1.1.0
Release:	0.1
License:	Apache-like
Group:		Libraries
%if %{without snap}
#Source0:	ftp://ftp.openssl.org/source/%{name}-%{version}.tar.gz
Source0:	https://www.openssl.org/source/%{name}-%{version}-%{subver}.tar.gz
# Source0-md5:	5073f45b5922992234396c7d8247196f
%else
Source1:	https://github.com/openssl/openssl/archive/OpenSSL_1_0_2-stable/%{name}-%{version}-dev.tar.gz
%endif
Source2:	%{name}.1.pl
Source3:	%{name}-ssl-certificate.sh
Source4:	%{name}-c_rehash.sh
Patch0:		%{name}-alpha-ccc.patch
Patch1:		%{name}-optflags.patch
Patch2:		%{name}-include.patch
Patch3:		%{name}-man-namespace.patch
Patch4:		%{name}-asflag.patch
Patch5:		%{name}-ca-certificates.patch
Patch6:		%{name}-ldflags.patch
Patch7:		%{name}-find.patch
Patch8:		pic.patch
Patch10:	%{name}_fix_for_x32.patch
Patch11:	engines-dir.patch
URL:		http://www.openssl.org/
BuildRequires:	bc
BuildRequires:	perl-devel >= 1:5.10.0
BuildRequires:	rpm-perlprov >= 4.1-13
BuildRequires:	rpmbuild(macros) >= 1.213
BuildRequires:	sed >= 4.0
Requires:	ca-certificates >= 20120623-1.1
Requires:	rpm-whiteout >= 1.7
Obsoletes:	SSLeay
Obsoletes:	SSLeay-devel
Obsoletes:	SSLeay-perl
Obsoletes:	libopenssl0
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

%package engines
Summary:	OpenSSL optional crypto engines
Summary(pl.UTF-8):	Opcjonalne silniki kryptograficzne dla OpenSSL-a
Group:		Libraries
Requires:	%{name} = %{version}-%{release}

%description engines
With OpenSSL 0.9.6, a new component was added to support alternative
cryptography implementations, most commonly for interfacing with
external crypto devices (eg. accelerator cards). This component is
called ENGINE.

There are currently built-in ENGINE implementations for the following
crypto devices:

- CryptoSwift
- Compaq Atalla
- nCipher CHIL
- Nuron
- Broadcom uBSec

In addition, dynamic binding to external ENGINE implementations is now
provided by a special ENGINE called "dynamic".

%description engines -l pl.UTF-8
Począwszy od OpenSSL-a 0.9.6 został dodany nowy komponent, mający
wspierać alternatywne implementacje kryptografii, przeważnie
współpracujące z zewnętrznymi urządzeniami kryptograficznymi (np.
kartami akceleratorów). Komponent ten jest nazywany SILNIKIEM (ang.
ENGINE).

Obecnie istnieją wbudowane implementacje silników dla następujących
urządzeń kryptograficznych:
- CryptoSwift
- Compaq Atalla
- nCipher CHIL
- Nuron
- Broadcom uBSec

Ponadto zapewnione jest dynamiczne wiązanie dla zewnętrznych
implementacji silników poprzez specjalny silnik o nazwie "dynamic".

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
Obsoletes:	libopenssl0-devel

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
%if %{with snap}
%setup -qcT -a1
mv %{name}-OpenSSL_1_0_2-stable/* .
%else
%setup -q %{?subver:-n %{name}-%{version}-%{subver}}
%endif
#%patch0 -p1 # alpha patch from year 2000 - drop it
#%patch1 -p1 # flags list has been nuked (thank god!)
#%patch2 -p1 # openssl include subdir. check this
#%patch3 -p1 # patched Makefile.org no longer exists
#%patch4 -p1 # patched Makefile.org no longer exists
#%patch5 -p1 # check
#%patch6 -p1 # patched Makefile.org no longer exists
%patch7 -p1
%patch8 -p1
%ifarch x32
%patch10 -p1
%endif
%patch11 -p1

%build
touch Makefile.*

# util/perlpath.pl no longer exists
#%{__perl} util/perlpath.pl %{__perl}

OPTFLAGS="%{rpmcflags} %{rpmcppflags} %{?with_purify:-DPURIFY}" \
PERL="%{__perl}" \
%{__perl} ./Configure \
	--prefix=%{_prefix} \
	--openssldir=%{_sysconfdir}/%{name} \
	--libdir=%{_lib} \
	shared \
	threads \
	%{?with_sslv2:enable-ssl2}%{!?with_sslv2:no-ssl2} \
	%{?with_sslv3:enable-ssl3}%{!?with_sslv3:no-ssl3} \
	%{!?with_zlib:no-}zlib \
	enable-cms \
	enable-idea \
	enable-md2 \
	enable-mdc2 \
	enable-rc5 \
	enable-rfc3779 \
	enable-seed \
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
	linux-alpha+bwx-gcc
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
%ifarch armv4 armv5 armv5t armv5te armv5tel
	linux-armv4
%endif

v=$(awk -F= '/^VERSION/{print $2}' Makefile)
test "$v" = %{version}%{?subver:-%{subver}}%{?with_snap:-dev}

%{__make} -j1 all rehash %{?with_tests:tests} \
	CC="%{__cc}" \
	ASFLAG='$(CFLAG) -Wa,--noexecstack' \
	INSTALLTOP=%{_prefix}

# Rename POD sources of man pages. "openssl_" prefix is added to each
# manpage to avoid potential conflicts with other packages.

for dir in doc/{apps,ssl,crypto}; do
	cd $dir || exit 1;
	%{__perl} -pi -e 's/(\W)((?<!openssl_)\w+)(\(\d\))/$1openssl_$2$3/g; s/openssl_openssl/openssl/g;' *.pod;

	for pod in !(openssl*).pod; do
		mv -f $pod openssl_$pod;
	done
	cd ../..
done

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/%{name},%{_libdir}/%{name}} \
	$RPM_BUILD_ROOT{%{_mandir}/{pl/man1,man{1,3,5,7}},%{_datadir}/ssl} \
	$RPM_BUILD_ROOT/%{_lib}/engines \
	$RPM_BUILD_ROOT%{_pkgconfigdir}

%{__make} -j1 install \
	INSTALLTOP=%{_prefix} \
	INSTALL_PREFIX=$RPM_BUILD_ROOT \
	MANDIR=%{_mandir}

mv -f $RPM_BUILD_ROOT%{_libdir}/engines/* $RPM_BUILD_ROOT/%{_lib}/engines
mv -f $RPM_BUILD_ROOT%{_libdir}/lib*.so.*.* $RPM_BUILD_ROOT/%{_lib}
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libcrypto.*.*) $RPM_BUILD_ROOT%{_libdir}/libcrypto.so
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libssl.*.*) $RPM_BUILD_ROOT%{_libdir}/libssl.so

mv -f $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/misc/* $RPM_BUILD_ROOT%{_libdir}/%{name}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/misc

# not installed as individual utilities (see openssl dgst instead)
%{__rm} $RPM_BUILD_ROOT%{_mandir}/man1/{dss1,md2,md4,md5,mdc2,ripemd160,sha,sha1,sha224,sha256,sha384,sha512}.1

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
%doc CHANGES CHANGES.SSLeay LICENSE NEWS README doc/*.txt
%attr(755,root,root) /%{_lib}/libcrypto.so.*.*.*
%attr(755,root,root) /%{_lib}/libssl.so.*.*.*
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/certs
%dir %attr(700,root,root) %{_sysconfdir}/%{name}/private
%dir %{_datadir}/ssl

%files engines
%defattr(644,root,root,755)
%dir /%{_lib}/engines
%attr(755,root,root) /%{_lib}/engines/*.so

%files tools
%defattr(644,root,root,755)
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/openssl.cnf
%attr(755,root,root) %{_bindir}/c_rehash.sh
%attr(755,root,root) %{_bindir}/openssl
%attr(754,root,root) %{_bindir}/ssl-certificate

%dir %{_libdir}/%{name}
%attr(755,root,root) %{_libdir}/%{name}/CA.sh
%attr(755,root,root) %{_libdir}/%{name}/c_hash
%attr(755,root,root) %{_libdir}/%{name}/c_info
%attr(755,root,root) %{_libdir}/%{name}/c_issuer
%attr(755,root,root) %{_libdir}/%{name}/c_name

%{_mandir}/man1/openssl.1*
%{_mandir}/man1/openssl_asn1parse.1*
%{_mandir}/man1/openssl_ca.1*
%{_mandir}/man1/openssl_ciphers.1*
%{_mandir}/man1/openssl_cms.1*
%{_mandir}/man1/openssl_crl.1*
%{_mandir}/man1/openssl_crl2pkcs7.1*
%{_mandir}/man1/openssl_dgst.1*
%{_mandir}/man1/openssl_dhparam.1*
%{_mandir}/man1/openssl_dsa.1*
%{_mandir}/man1/openssl_dsaparam.1*
%{_mandir}/man1/openssl_ec.1*
%{_mandir}/man1/openssl_ecparam.1*
%{_mandir}/man1/openssl_enc.1*
%{_mandir}/man1/openssl_errstr.1*
%{_mandir}/man1/openssl_gendsa.1*
%{_mandir}/man1/openssl_genpkey.1*
%{_mandir}/man1/openssl_genrsa.1*
%{_mandir}/man1/openssl_nseq.1*
%{_mandir}/man1/openssl_ocsp.1*
%{_mandir}/man1/openssl_passwd.1*
%{_mandir}/man1/openssl_pkcs12.1*
%{_mandir}/man1/openssl_pkcs7.1*
%{_mandir}/man1/openssl_pkcs8.1*
%{_mandir}/man1/openssl_pkey.1*
%{_mandir}/man1/openssl_pkeyparam.1*
%{_mandir}/man1/openssl_pkeyutl.1*
%{_mandir}/man1/openssl_rand.1*
%{_mandir}/man1/openssl_req.1*
%{_mandir}/man1/openssl_rsa.1*
%{_mandir}/man1/openssl_rsautl.1*
%{_mandir}/man1/openssl_s_client.1*
%{_mandir}/man1/openssl_s_server.1*
%{_mandir}/man1/openssl_s_time.1*
%{_mandir}/man1/openssl_sess_id.1*
%{_mandir}/man1/openssl_smime.1*
%{_mandir}/man1/openssl_speed.1*
%{_mandir}/man1/openssl_spkac.1*
%{_mandir}/man1/openssl_ts.1*
%{_mandir}/man1/openssl_tsget.1*
%{_mandir}/man1/openssl_verify.1*
%{_mandir}/man1/openssl_version.1*
%{_mandir}/man1/openssl_x509.1*
%{_mandir}/man5/openssl_config.5*
%{_mandir}/man5/openssl_x509v3_config.5*
%lang(pl) %{_mandir}/pl/man1/openssl.1*

%files tools-perl
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/c_rehash
%attr(755,root,root) %{_libdir}/%{name}/CA.pl
%attr(755,root,root) %{_libdir}/%{name}/tsget
%{_mandir}/man1/openssl_CA.pl.1*
%{_mandir}/man1/openssl_c_rehash.1*

%files devel
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libcrypto.so
%attr(755,root,root) %{_libdir}/libssl.so
%{_includedir}/%{name}
%{_pkgconfigdir}/libcrypto.pc
%{_pkgconfigdir}/libssl.pc
%{_pkgconfigdir}/openssl.pc
%{_mandir}/man3/openssl*.3*
%{_mandir}/man7/openssl_des_modes.7*

%files static
%defattr(644,root,root,755)
%{_libdir}/libcrypto.a
%{_libdir}/libssl.a
