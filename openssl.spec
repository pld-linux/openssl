%include	/usr/lib/rpm/macros.perl
Summary:	OpenSSL Toolkit libraries for the "Secure Sockets Layer" (SSL v2/v3)
Summary(de):	Secure Sockets Layer (SSL)-Kommunikationslibrary
Summary(es):	Biblioteca C que suministra algoritmos y protocolos criptogrАficos.
Summary(fr):	Utilitaires de communication SSL (Secure Sockets Layer)
Summary(pl):	Biblioteki OpenSSL (SSL v2/v3)
Summary(pt_BR):	Uma biblioteca C que fornece vАrios algoritmos e protocolos criptogrАficos.
Summary(ru):	Библиотеки и утилиты для соединений через Secure Sockets Layer
Summary(uk):	Б╕бл╕отеки та утил╕ти для з'╓днань через Secure Sockets Layer
Name:		openssl
Version:	0.9.6d
Release:	1
License:	Apache-style License
Vendor:		The OpenSSL Project
Group:		Libraries
Source0:	ftp://ftp.openssl.org/source/%{name}-%{version}.tar.gz
Source1:	%{name}-ca-bundle.crt
Patch0:		%{name}-alpha-ccc.patch
# patch1 is only for 0.9.6a version. This version isn't binary
# compatibile with 0.9.6 but have this same soname.
Patch1:		%{name}-soname.patch
Patch2:		%{name}-optflags.patch
Patch3:		%{name}-nocrypt.patch
Patch4:		%{name}-globalCA.diff
BuildRequires:	perl-devel >= 5.6.1
BuildRequires:	textutils
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Obsoletes:	SSLeay
Obsoletes:	SSLeay-devel
Obsoletes:	SSLeay-perl
Obsoletes:	libopenssl0

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

%description -l de
Openssl enthДlt das OpenSSL Zertifikatsmanagementtool und shared
libraries, die verschiedene VerschlЭsselungs- und
EntschlЭsselungsalgorithmen und -protokolle, wie DES, RC4, RSA und SSL
zur VerfЭgung stellen.

%description -l es
Biblioteca C que suministra algoritmos y protocolos criptogrАficos.

%description -l fr
OpenSSL est un outiil de gestion des certificats et les librairies
partagees qui fournit plusieurs protocoles et algorithmes de
codage/decodage, incluant DES, RC4, RSA et SSL.

%description -l pl
Implementacja protokoЁСw kryptograficznych Secure Socket Layer (SSL)
v2/v3 oraz Transport Layer Security (TLS v1).

%description -l pt_BR
Uma biblioteca C que fornece vАrios algoritmos e protocolos
criptogrАficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas
compartilhadas e utilitАrios.

%description -l ru
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL.

%description -l uk
Програма openssl для роботи з сертиф╕катами та б╕бл╕отеки сп╕льного
користування, що реал╕зують велику к╕льк╕сть криптограф╕чних
алгоритм╕в, включаючи DES, RC4, RSA та SSL.

%package tools
Summary:	OpenSSL command line tool and utilities
Summary(pl):	Zestaw narzЙdzi i skryptСw
Group:		Applications/Communications
Requires:	%{name} = %{version}

%description tools
The OpenSSL Toolkit cmdline tool openssl and utility scripts.

%description tools -l pl
Zestaw narzЙdzi i skryptСw wywoЁywanych z linii poleceЯ.

%package tools-perl
Summary:	OpenSSL utilities written in Perl
Summary(pl):	NarzЙdzia OpenSSL napisane w perlu
Group:		Applications/Communications
Requires:	%{name} = %{version}

%description tools-perl
OpenSSL Toolkit tools written in Perl.

%description tools-perl -l pl
NarzЙdzia OpenSSL napisane w perlu.

%package devel
Summary:	Development part of OpenSSL Toolkit libraries
Summary(de):	Secure Sockets Layer Kommunikationslibrary: statische libraries+header
Summary(es):	Bibliotecas y archivos de inclusiСn para desarrollo OpenSSL
Summary(fr):	Librairies statiques, headers et utilitaires pour communication SSL
Summary(pl):	CzЙ╤Ф bibiloteki OpenSSL przeznaczona dla programistСw
Summary(pt_BR):	Bibliotecas e arquivos de inclusЦo para desenvolvimento OpenSSL
Summary(ru):	Библиотеки, хедеры и утилиты для Secure Sockets Layer
Summary(uk):	Б╕бл╕отеки, хедери та утил╕ти для Secure Sockets Layer
Group:		Development/Libraries
Requires:	%{name} = %{version}
Obsoletes:	libopenssl0-devel

%description devel
Development part of OpenSSL library.

%description devel -l es
Bibliotecas y archivos de inclusiСn para desarrollo OpenSSL

%description devel -l pl
CzЙ╤Ф bibiloteki OpenSSL przeznaczona dla programistСw.

%description devel -l pt_BR
Uma biblioteca C que fornece vАrios algoritmos e protocolos
criptogrАficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas e
arquivos de inclusЦo para desenvolvimento.

%description devel -l ru
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL. Включает библиотеки и хедеры для разработки приложений
с использованием SSL.

%description devel -l uk
Програма openssl для роботи з сертиф╕катами та б╕бл╕отеки сп╕льного
користування, що реал╕зують велику к╕льк╕сть криптограф╕чних
алгоритм╕в, включаючи DES, RC4, RSA та SSL. М╕стить б╕бл╕отеки та
хедери для розробки програм з використанням SSL.

%package static
Summary:	Static OpenSSL libraries
Summary(pl):	Statyczne wersje bibliotek z OpenSSL
Summary(pt_BR):	Bibliotecas estАticas para desenvolvimento com openssl
Summary(ru):	Статические библиотеки разработчика для OpenSSL
Summary(uk):	Статичн╕ б╕бл╕отеки програм╕ста для OpenSSL
Group:		Development/Libraries
Requires:	%{name}-devel = %{version}

%description static
Static OpenSSL Toolkit libraries.

%description static -l pl
Statyczne wersje bibliotek z OpenSSL.

%description static -l pt_BR
Bibliotecas estАticas para desenvolvimento com openssl.

%description static -l ru
Программа openssl для работы с сертификатами и разделяемые библиотеки,
которые реализуют множетсво криптографических алгоритмов, включая DES,
RC4, RSA и SSL. Включает статические библиотеки для разработки
приложений с использованием OpenSSL.

%description static -l uk
Програма openssl для роботи з сертиф╕катами та б╕бл╕отеки сп╕льного
користування, що реал╕зують велику к╕льк╕сть криптограф╕чних
алгоритм╕в, включаючи DES, RC4, RSA та SSL. М╕стить статичн╕
б╕бл╕отеки для розробки програм з використанням SSL.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1

%build
for f in ` grep -r "%{_prefix}/local/bin/perl" . | cut -d":" -f1`; do
perl -pi -e 's#%{_prefix}/local/bin/perl#%{_bindir}/perl#g' $f
done

touch Makefile.*

perl util/perlpath.pl %{_bindir}/perl

OPTFLAGS="%{rpmcflags}"
export OPTFLAGS
%ifarch i386 i486
./Configure --openssldir=%{_var}/lib/%{name} linux-elf shared 386
%endif
%ifarch i586 i686 athlon
./Configure --openssldir=%{_var}/lib/%{name} linux-elf shared
%endif
%ifarch ppc
./Configure --openssldir=%{_var}/lib/%{name} linux-ppc shared
%endif
%ifarch alpha
./Configure --openssldir=%{_var}/lib/%{name} threads linux-alpha+bwx-gcc shared
%endif
%ifarch sparc
./Configure --openssldir=%{_var}/lib/%{name} threads linux-sparcv8 shared
%endif

%{__make} CC="%{__cc}"
%{__make} rehash CC="%{__cc}"

# Conv PODs to man pages. "openssl_" prefix is added to each manpage
# to avoid potential conflicts with others packages.
center="OpenSSL 0.9.6"
rel="OpenSSL 0.9.6"

cd doc/apps || exit 1
perl -pi -e 's/(\W)((?<!openssl_)\w+)(\(\d\))/$1openssl_$2$3/g; s/openssl_openssl/openssl/g;' *.pod;

for pod in *.pod; do
	if [ $pod != "openssl.pod" ]; then
		mv -f $pod openssl_$pod;
		pod=openssl_$pod;
	fi

	sec=1
	if [ $pod = "openssl_config.pod" ]; then
		sec=5
	fi

	manpage=`basename $pod .pod`.$sec;
	pod2man --section="$sec" --release="$rel" --center="$center" \
		$pod > $manpage;
	echo "$manpage";
done
cd ..

sec=3
for dir in ssl crypto; do
	cd $dir || exit 1;
	if [ $dir = "ssl" ]; then
		rel="OpenSSL SSL/TLS library"
	elif [ $dir = "crypto" ]; then
		rel="OpenSSL cryptographic library"
	fi

	perl -p -i -e 's/(\W)((?<!openssl_)\w+)(\(\d\))/$1openssl_$2$3/g; s/openssl_openssl/openssl/g;' *.pod;

	for pod in *.pod; do
		sec=`[ "$pod" = "des_modes.pod" ] && echo 7 || echo 3`;
		mv -f $pod openssl_$pod;
		pod=openssl_$pod;
		manpage=`basename $pod .pod`.$sec;
		pod2man --section="$sec" --release="$rel" --center=" " $pod > $manpage;
		echo "$manpage";
	done
	cd ..
done

#cd perl
#perl Makefile.PL
#make

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/%{name},%{_libdir}/%{name}} \
	$RPM_BUILD_ROOT{%{_mandir}/man{1,3,5,7},%{_datadir}/ssl}

%{__make} install \
	INSTALLTOP=%{_prefix} \
	INSTALL_PREFIX=$RPM_BUILD_ROOT

install %{SOURCE1}  $RPM_BUILD_ROOT%{_datadir}/ssl/ca-bundle.crt
install libRSAglue.a libcrypto.a libssl.a $RPM_BUILD_ROOT%{_libdir}
install lib*.so.*.* $RPM_BUILD_ROOT%{_libdir}
ln -sf libcrypto.so.*.* $RPM_BUILD_ROOT%{_libdir}/libcrypto.so
ln -sf libssl.so.*.* $RPM_BUILD_ROOT%{_libdir}/libssl.so

mv -f $RPM_BUILD_ROOT%{_var}/lib/%{name}/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/%{name}
ln -s %{_sysconfdir}/%{name}/openssl.cnf \
	$RPM_BUILD_ROOT%{_var}/lib/%{name}/%{name}.cnf

mv -f $RPM_BUILD_ROOT%{_var}/lib/%{name}/misc/* $RPM_BUILD_ROOT%{_libdir}/%{name}
rm -rf $RPM_BUILD_ROOT%{_var}/lib/%{name}/misc

mv -f $RPM_BUILD_ROOT%{_bindir}/c_rehash $RPM_BUILD_ROOT%{_libdir}/%{name}

find $RPM_BUILD_ROOT%{_mandir} -type f | xargs rm -f
install doc/apps/*.1 $RPM_BUILD_ROOT%{_mandir}/man1
install doc/apps/*.5 $RPM_BUILD_ROOT%{_mandir}/man5
install doc/ssl/*.3 doc/crypto/*.3 $RPM_BUILD_ROOT%{_mandir}/man3
install doc/crypto/*.7 $RPM_BUILD_ROOT%{_mandir}/man7

gzip -9nf CHANGES CHANGES.SSLeay LICENSE NEWS README doc/*.txt

%post   -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/lib*.so.*.*
%doc *.gz doc/*.txt.gz doc/openssl_button.gif doc/openssl_button.html

%files tools
%defattr(644,root,root,755)
%dir %{_sysconfdir}/%{name}
%dir %{_var}/lib/%{name}
%dir %{_var}/lib/%{name}/private
%dir %{_var}/lib/%{name}/certs

%verify(not md5 size mtime) %config(noreplace) %{_sysconfdir}/%{name}/openssl.cnf
%verify(not md5 size mtime) %config(noreplace) %{_var}/lib/%{name}/openssl.cnf
%dir %{_datadir}/ssl
%verify(not md5 size mtime) %config(noreplace)%{_datadir}/ssl/ca-bundle.crt

%attr(755,root,root) %{_bindir}/%{name}
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
%{_mandir}/man1/openssl_crl.1*
%{_mandir}/man1/openssl_crl2pkcs7.1*
%{_mandir}/man1/openssl_dgst.1*
%{_mandir}/man1/openssl_dhparam.1*
%{_mandir}/man1/openssl_dsa.1*
%{_mandir}/man1/openssl_dsaparam.1*
%{_mandir}/man1/openssl_enc.1*
%{_mandir}/man1/openssl_gendsa.1*
%{_mandir}/man1/openssl_genrsa.1*
%{_mandir}/man1/openssl_nseq.1*
%{_mandir}/man1/openssl_passwd.1*
%{_mandir}/man1/openssl_pkcs12.1*
%{_mandir}/man1/openssl_pkcs7.1*
%{_mandir}/man1/openssl_pkcs8.1*
%{_mandir}/man1/openssl_rand.1*
%{_mandir}/man1/openssl_req.1*
%{_mandir}/man1/openssl_rsa.1*
%{_mandir}/man1/openssl_s_client.1*
%{_mandir}/man1/openssl_s_server.1*
%{_mandir}/man1/openssl_sess_id.1*
%{_mandir}/man1/openssl_smime.1*
%{_mandir}/man1/openssl_speed.1*
%{_mandir}/man1/openssl_spkac.1*
%{_mandir}/man1/openssl_verify.1*
%{_mandir}/man1/openssl_version.1*
%{_mandir}/man1/openssl_x509.1*
%{_mandir}/man5/*.5*

%files tools-perl
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/%{name}/CA.pl
%attr(755,root,root) %{_libdir}/%{name}/der_chop
%attr(755,root,root) %{_libdir}/%{name}/c_rehash
%{_mandir}/man1/openssl_CA.pl.1*

%files devel
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/lib*.so
%{_includedir}/%{name}
%{_mandir}/man3/*.3*

%files static
%defattr(644,root,root,755)
%{_libdir}/lib*.a
