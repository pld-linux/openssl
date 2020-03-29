#
# Conditional build:
%bcond_without	tests	# don't perform "make tests"
%bcond_without	zlib	# zlib: note - enables CVE-2012-4929 vulnerability
%bcond_with	sslv2	# SSLv2: note - many flaws http://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_2.0
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
# Version 1.1.1 is LTS, supported until 2023-09-11.
# https://www.openssl.org/about/releasestrat.html
Version:	1.1.1e
Release:	1
License:	Apache-like
Group:		Libraries
Source0:	https://www.openssl.org/source/%{name}-%{version}.tar.gz
# Source0-md5:	baeff2a64d2f3d7e0a69b677c9977b57
Source2:	%{name}.1.pl
Source3:	%{name}-ssl-certificate.sh
Source4:	%{name}-c_rehash.sh
Patch1:		%{name}-optflags.patch

Patch3:		%{name}-man-namespace.patch
Patch4:		bug-11378.patch
Patch5:		%{name}-ca-certificates.patch
Patch6:		%{name}-no-win32.patch
Patch7:		%{name}-find.patch
Patch8:		pic.patch

Patch11:	engines-dir.patch
URL:		http://www.openssl.org/
BuildRequires:	libsctp-devel
BuildRequires:	perl-devel >= 1:5.10.0
BuildRequires:	pkgconfig
BuildRequires:	rpm-perlprov >= 4.1-13
BuildRequires:	rpmbuild(macros) >= 1.213
BuildRequires:	sed >= 4.0
BuildRequires:	zlib-devel
Requires:	ca-certificates >= 20141019-3
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
%{__mv} %{name}-OpenSSL_1_1_0-stable/* .
%else
%setup -q %{?subver:-n %{name}-%{version}-%{subver}}
%endif
%patch1 -p1

%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1

%patch11 -p1

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
	%{?with_sslv2:enable-ssl2}%{!?with_sslv2:no-ssl2} \
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

v=$(awk -F= '/^VERSION/{print $2}' Makefile)
test "$v" = %{version}%{?subver:-%{subver}}%{?with_snap:-dev}

# fails with enable-sctp as of 1.1.1
%{__rm} test/recipes/80-test_ssl_new.t

%{__make} -j1 all %{?with_tests:tests} \
	CC="%{__cc}" \
	OPTFLAGS="%{rpmcflags} %{rpmcppflags}" \
	INSTALLTOP=%{_prefix}

# Rename POD sources of man pages. "openssl-" prefix is added to each
# manpage to avoid potential conflicts with other packages.
# openssl-man-namespace.patch mostly marks these pages with "openssl-" prefix.

for podfile in $(grep -rl '^openssl-' doc/man*); do
	dir=$(dirname "$podfile")
	base=$(basename "$podfile")
	%{__mv} "$podfile" "$dir/openssl-$base"
done

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/%{name},%{_libdir}/%{name}} \
	$RPM_BUILD_ROOT{%{_mandir}/{pl/man1,man{1,3,5,7}},%{_datadir}/ssl} \
	$RPM_BUILD_ROOT%{_pkgconfigdir}

%{__make} -j1 install \
	CC="%{__cc}" \
	DESTDIR=$RPM_BUILD_ROOT

%{__mv} $RPM_BUILD_ROOT%{_libdir}/lib*.so.*.* $RPM_BUILD_ROOT/%{_lib}
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libcrypto.*.*) $RPM_BUILD_ROOT%{_libdir}/libcrypto.so
ln -sf /%{_lib}/$(basename $RPM_BUILD_ROOT/%{_lib}/libssl.*.*) $RPM_BUILD_ROOT%{_libdir}/libssl.so

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
%doc CHANGES LICENSE NEWS README doc/*.txt
%attr(755,root,root) /%{_lib}/libcrypto.so.*.*
%attr(755,root,root) /%{_lib}/libssl.so.*.*
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/certs
%dir %attr(700,root,root) %{_sysconfdir}/%{name}/private
%dir %{_datadir}/ssl

%files engines
%defattr(644,root,root,755)
%dir /%{_lib}/engines-1.1
%attr(755,root,root) /%{_lib}/engines-1.1/*.so

%files tools
%defattr(644,root,root,755)
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/ct_log_list.cnf
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/openssl.cnf
%attr(755,root,root) %{_bindir}/c_rehash.sh
%attr(755,root,root) %{_bindir}/openssl
%attr(754,root,root) %{_bindir}/ssl-certificate
%{_mandir}/man1/openssl.1*
%{_mandir}/man1/openssl-asn1parse.1*
%{_mandir}/man1/openssl-ca.1*
%{_mandir}/man1/openssl-ciphers.1*
%{_mandir}/man1/openssl-cms.1*
%{_mandir}/man1/openssl-crl.1*
%{_mandir}/man1/openssl-crl2pkcs7.1*
%{_mandir}/man1/openssl-dgst.1*
%{_mandir}/man1/openssl-dhparam.1*
%{_mandir}/man1/openssl-dsa.1*
%{_mandir}/man1/openssl-dsaparam.1*
%{_mandir}/man1/openssl-ec.1*
%{_mandir}/man1/openssl-ecparam.1*
%{_mandir}/man1/openssl-enc.1*
%{_mandir}/man1/openssl-engine.1*
%{_mandir}/man1/openssl-errstr.1*
%{_mandir}/man1/openssl-gendsa.1*
%{_mandir}/man1/openssl-genpkey.1*
%{_mandir}/man1/openssl-genrsa.1*
%{_mandir}/man1/openssl-list.1*
%{_mandir}/man1/openssl-nseq.1*
%{_mandir}/man1/openssl-ocsp.1*
%{_mandir}/man1/openssl-passwd.1*
%{_mandir}/man1/openssl-pkcs12.1*
%{_mandir}/man1/openssl-pkcs7.1*
%{_mandir}/man1/openssl-pkcs8.1*
%{_mandir}/man1/openssl-pkey.1*
%{_mandir}/man1/openssl-pkeyparam.1*
%{_mandir}/man1/openssl-pkeyutl.1*
%{_mandir}/man1/openssl-prime.1*
%{_mandir}/man1/openssl-rand.1*
%{_mandir}/man1/openssl-rehash.1*
%{_mandir}/man1/openssl-req.1*
%{_mandir}/man1/openssl-rsa.1*
%{_mandir}/man1/openssl-rsautl.1*
%{_mandir}/man1/openssl-s_client.1*
%{_mandir}/man1/openssl-s_server.1*
%{_mandir}/man1/openssl-s_time.1*
%{_mandir}/man1/openssl-sess_id.1*
%{_mandir}/man1/openssl-smime.1*
%{_mandir}/man1/openssl-speed.1*
%{_mandir}/man1/openssl-spkac.1*
%{_mandir}/man1/openssl-srp.1*
%{_mandir}/man1/openssl-storeutl.1*
%{_mandir}/man1/openssl-ts.1*
%{_mandir}/man1/openssl-tsget.1*
%{_mandir}/man1/openssl-verify.1*
%{_mandir}/man1/openssl-version.1*
%{_mandir}/man1/openssl-x509.1*
%{_mandir}/man5/openssl-config.5*
%{_mandir}/man5/openssl-x509v3_config.5*
%lang(pl) %{_mandir}/pl/man1/openssl.1*

%files tools-perl
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/c_rehash
%dir %{_libdir}/%{name}
%attr(755,root,root) %{_libdir}/%{name}/CA.pl
%attr(755,root,root) %{_libdir}/%{name}/tsget
%attr(755,root,root) %{_libdir}/%{name}/tsget.pl
%{_mandir}/man1/CA.pl.1*
%{_mandir}/man1/c_rehash.1*

%files devel
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libcrypto.so
%attr(755,root,root) %{_libdir}/libssl.so
%{_includedir}/%{name}
%{_pkgconfigdir}/libcrypto.pc
%{_pkgconfigdir}/libssl.pc
%{_pkgconfigdir}/openssl.pc
%{_mandir}/man3/ACCESS_DESCRIPTION_*.3*
%{_mandir}/man3/ADMISSION*.3*
%{_mandir}/man3/ASId*.3*
%{_mandir}/man3/ASRange_*.3*
%{_mandir}/man3/ASN1_*.3*
%{_mandir}/man3/ASYNC_*.3*
%{_mandir}/man3/AUTHORITY_*.3*
%{_mandir}/man3/BASIC_CONSTRAINTS_*.3*
%{_mandir}/man3/BF_*.3*
%{_mandir}/man3/BIO_*.3*
%{_mandir}/man3/BN_*.3*
%{_mandir}/man3/BUF_*.3*
%{_mandir}/man3/CERTIFICATEPOLICIES_*.3*
%{_mandir}/man3/CMS_*.3*
%{_mandir}/man3/CONF_*.3*
%{_mandir}/man3/CRL_DIST_POINTS_*.3*
%{_mandir}/man3/CRYPTO_*.3*
%{_mandir}/man3/CTLOG_*.3*
%{_mandir}/man3/CT_POLICY_*.3*
%{_mandir}/man3/DECLARE_*.3*
%{_mandir}/man3/DEFINE_*.3*
%{_mandir}/man3/DES_*.3*
%{_mandir}/man3/DH_*.3*
%{_mandir}/man3/DHparams_*.3*
%{_mandir}/man3/DIRECTORYSTRING_*.3*
%{_mandir}/man3/DISPLAYTEXT_*.3*
%{_mandir}/man3/DIST_POINT_*.3*
%{_mandir}/man3/DSA_*.3*
%{_mandir}/man3/DSAparams_*.3*
%{_mandir}/man3/DTLS_*.3*
%{_mandir}/man3/DTLSv1_*.3*
%{_mandir}/man3/ECDH_*.3*
%{_mandir}/man3/ECDSA_*.3*
%{_mandir}/man3/ECPARAMETERS_*.3*
%{_mandir}/man3/ECPKPARAMETERS_*.3*
%{_mandir}/man3/ECPKParameters_*.3*
%{_mandir}/man3/EC_*.3*
%{_mandir}/man3/EDIPARTYNAME_*.3*
%{_mandir}/man3/ENGINE_*.3*
%{_mandir}/man3/ERR_*.3*
%{_mandir}/man3/ESS_*.3*
%{_mandir}/man3/EVP_*.3*
%{_mandir}/man3/EXTENDED_KEY_USAGE_*.3*
%{_mandir}/man3/GENERAL_*.3*
%{_mandir}/man3/GEN_SESSION_CB.3*
%{_mandir}/man3/HMAC*.3*
%{_mandir}/man3/IMPLEMENT_*.3*
%{_mandir}/man3/IPAddress*.3*
%{_mandir}/man3/ISSUING_DIST_POINT_*.3*
%{_mandir}/man3/LHASH*.3*
%{_mandir}/man3/MD2*.3*
%{_mandir}/man3/MD4*.3*
%{_mandir}/man3/MD5*.3*
%{_mandir}/man3/MDC2*.3*
%{_mandir}/man3/NAME_CONSTRAINTS_*.3*
%{_mandir}/man3/NAMING_AUTHORITY*.3*
%{_mandir}/man3/NETSCAPE_*.3*
%{_mandir}/man3/NOTICEREF_*.3*
%{_mandir}/man3/OBJ_*.3*
%{_mandir}/man3/OCSP_*.3*
%{_mandir}/man3/OPENSSL_*.3*
%{_mandir}/man3/OSSL*.3*
%{_mandir}/man3/OTHERNAME_*.3*
%{_mandir}/man3/OpenSSL_*.3*
%{_mandir}/man3/PBE2PARAM_*.3*
%{_mandir}/man3/PBEPARAM_*.3*
%{_mandir}/man3/PBKDF2PARAM_*.3*
%{_mandir}/man3/PEM_*.3*
%{_mandir}/man3/PKCS12_*.3*
%{_mandir}/man3/PKCS5_*.3*
%{_mandir}/man3/PKCS7_*.3*
%{_mandir}/man3/PKCS8_*.3*
%{_mandir}/man3/PKEY_*.3*
%{_mandir}/man3/POLICYINFO_*.3*
%{_mandir}/man3/POLICYQUALINFO_*.3*
%{_mandir}/man3/POLICY_*.3*
%{_mandir}/man3/PROFESSION_INFO*.3*
%{_mandir}/man3/PROXY_*.3*
%{_mandir}/man3/RAND_*.3*
%{_mandir}/man3/RC4*.3*
%{_mandir}/man3/RIPEMD160*.3*
%{_mandir}/man3/RSAPrivateKey_*.3*
%{_mandir}/man3/RSAPublicKey_*.3*
%{_mandir}/man3/RSA_*.3*
%{_mandir}/man3/SCRYPT_PARAMS*.3*
%{_mandir}/man3/SCT_*.3*
%{_mandir}/man3/SHA1*.3*
%{_mandir}/man3/SHA224*.3*
%{_mandir}/man3/SHA256*.3*
%{_mandir}/man3/SHA384*.3*
%{_mandir}/man3/SHA512*.3*
%{_mandir}/man3/SMIME_*.3*
%{_mandir}/man3/SSL_*.3*
%{_mandir}/man3/SSLv23_*.3*
%{_mandir}/man3/SSLv3_*.3*
%{_mandir}/man3/SXNET_*.3*
%{_mandir}/man3/SXNETID_*.3*
%{_mandir}/man3/TLS_*.3*
%{_mandir}/man3/TLSv1_*.3*
%{_mandir}/man3/TS_*.3*
%{_mandir}/man3/UI*.3*
%{_mandir}/man3/USERNOTICE_*.3*
%{_mandir}/man3/X509_*.3*
%{_mandir}/man3/X509V3_*.3*
%{_mandir}/man3/X509v3_*.3*
%{_mandir}/man3/custom_ext_*.3*
%{_mandir}/man3/d2i_*.3*
%{_mandir}/man3/i2d_*.3*
%{_mandir}/man3/i2o_*.3*
%{_mandir}/man3/i2t_*.3*
%{_mandir}/man3/lh_TYPE_*.3*
%{_mandir}/man3/o2i_*.3*
%{_mandir}/man3/pem_password_cb.3*
%{_mandir}/man3/sk_TYPE_*.3*
%{_mandir}/man3/ssl_ct_validation_cb.3*
%{_mandir}/man7/openssl.7*
%{_mandir}/man7/openssl-bio.7*
%{_mandir}/man7/openssl-crypto.7*
%{_mandir}/man7/openssl-ct.7*
%{_mandir}/man7/openssl-des_modes.7*
%{_mandir}/man7/openssl-Ed25519.7*
%{_mandir}/man7/openssl-Ed448.7*
%{_mandir}/man7/openssl-evp.7*
%{_mandir}/man7/openssl-passphrase-encoding.7*
%{_mandir}/man7/openssl-RAND.7*
%{_mandir}/man7/openssl-RAND_DRBG.7*
%{_mandir}/man7/openssl-scrypt.7*
%{_mandir}/man7/openssl-SM2.7*
%{_mandir}/man7/openssl-ssl.7*
%{_mandir}/man7/openssl-X25519.7*
%{_mandir}/man7/openssl-X448.7*
%{_mandir}/man7/openssl-x509.7*
%{_mandir}/man7/ossl_store.7*
%{_mandir}/man7/ossl_store-file.7*
%{_mandir}/man7/proxy-certificates.7*
%{_mandir}/man7/RSA-PSS.7.gz

%files static
%defattr(644,root,root,755)
%{_libdir}/libcrypto.a
%{_libdir}/libssl.a
