#
# Conditional build:
%bcond_with purify	# Compile openssl with \-DPURIFY, useful when one wants to
			# use valgrind debugger against openssl-linked programs
%include	/usr/lib/rpm/macros.perl
Summary:	OpenSSL Toolkit libraries for the "Secure Sockets Layer" (SSL v2/v3)
Summary(de):	Secure Sockets Layer (SSL)-Kommunikationslibrary
Summary(es):	Biblioteca C que suministra algoritmos y protocolos criptogr�ficos
Summary(fr):	Utilitaires de communication SSL (Secure Sockets Layer)
Summary(pl):	Biblioteki OpenSSL (SSL v2/v3)
Summary(pt_BR):	Uma biblioteca C que fornece v�rios algoritmos e protocolos criptogr�ficos
Summary(ru):	���������� � ������� ��� ���������� ����� Secure Sockets Layer
Summary(uk):	��̦����� �� ���̦�� ��� �'������ ����� Secure Sockets Layer
Name:		openssl
Version:	0.9.8d
Release:	1
License:	Apache-style License
Group:		Libraries
Source0:	ftp://ftp.openssl.org/source/%{name}-%{version}.tar.gz
# Source0-md5:	8ed1853538e1d05a1f5ada61ebf8bffa
Source1:	%{name}-ca-bundle.crt
Source2:	%{name}.1.pl
Source3:	%{name}-ssl-certificate.sh
Patch0:		%{name}-alpha-ccc.patch
Patch1:		%{name}-optflags.patch
Patch2:		%{name}-globalCA.diff
Patch3:		%{name}-include.patch
Patch4:		%{name}-md5-sparcv9.patch
Patch5:		%{name}-libvar.patch
URL:		http://www.openssl.org/
BuildRequires:	perl-devel >= 1:5.6.1
BuildRequires:	rpm-perlprov >= 4.1-13
BuildRequires:	rpmbuild(macros) >= 1.213
BuildRequires:	sed >= 4.0
Obsoletes:	SSLeay
Obsoletes:	SSLeay-devel
Obsoletes:	SSLeay-perl
Obsoletes:	libopenssl0
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

%description -l de
Openssl enth�lt das OpenSSL Zertifikatsmanagementtool und shared
libraries, die verschiedene Verschl�sselungs- und
Entschl�sselungsalgorithmen und -protokolle, wie DES, RC4, RSA und SSL
zur Verf�gung stellen.

%description -l es
Biblioteca C que suministra algoritmos y protocolos criptogr�ficos.

%description -l fr
OpenSSL est un outiil de gestion des certificats et les librairies
partagees qui fournit plusieurs protocoles et algorithmes de
codage/decodage, incluant DES, RC4, RSA et SSL.

%description -l pl
Implementacja protoko��w kryptograficznych Secure Socket Layer (SSL)
v2/v3 oraz Transport Layer Security (TLS v1).

%description -l pt_BR
Uma biblioteca C que fornece v�rios algoritmos e protocolos
criptogr�ficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas
compartilhadas e utilit�rios.

%description -l ru
��������� openssl ��� ������ � ������������� � ����������� ����������,
������� ��������� ��������� ����������������� ����������, ������� DES,
RC4, RSA � SSL.

%description -l uk
�������� openssl ��� ������ � �����Ʀ������ �� ¦�̦����� �Ц������
������������, �� ���̦����� ������ ˦��˦��� ���������Ʀ����
�������ͦ�, ��������� DES, RC4, RSA �� SSL.

%package tools
Summary:	OpenSSL command line tool and utilities
Summary(pl):	Zestaw narz�dzi i skrypt�w
Group:		Applications/Communications
Requires:	%{name} = %{version}-%{release}

%description tools
The OpenSSL Toolkit cmdline tool openssl and utility scripts.

%description tools -l pl
Zestaw narz�dzi i skrypt�w wywo�ywanych z linii polece�.

%package tools-perl
Summary:	OpenSSL utilities written in Perl
Summary(pl):	Narz�dzia OpenSSL napisane w perlu
Group:		Applications/Communications
Requires:	%{name} = %{version}-%{release}

%description tools-perl
OpenSSL Toolkit tools written in Perl.

%description tools-perl -l pl
Narz�dzia OpenSSL napisane w perlu.

%package devel
Summary:	Development part of OpenSSL Toolkit libraries
Summary(de):	Secure Sockets Layer Kommunikationslibrary: statische libraries+header
Summary(es):	Bibliotecas y archivos de inclusi�n para desarrollo OpenSSL
Summary(fr):	Librairies statiques, headers et utilitaires pour communication SSL
Summary(pl):	Cz�� bibiloteki OpenSSL przeznaczona dla programist�w
Summary(pt_BR):	Bibliotecas e arquivos de inclus�o para desenvolvimento OpenSSL
Summary(ru):	����������, ������ � ������� ��� Secure Sockets Layer
Summary(uk):	��̦�����, ������ �� ���̦�� ��� Secure Sockets Layer
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
Obsoletes:	libopenssl0-devel

%description devel
Development part of OpenSSL library.

%description devel -l es
Bibliotecas y archivos de inclusi�n para desarrollo OpenSSL

%description devel -l pl
Cz�� biblioteki OpenSSL przeznaczona dla programist�w.

%description devel -l pt_BR
Uma biblioteca C que fornece v�rios algoritmos e protocolos
criptogr�ficos, incluindo DES, RC4, RSA e SSL. Inclui bibliotecas e
arquivos de inclus�o para desenvolvimento.

%description devel -l ru
��������� openssl ��� ������ � ������������� � ����������� ����������,
������� ��������� ��������� ����������������� ����������, ������� DES,
RC4, RSA � SSL. �������� ���������� � ������ ��� ���������� ����������
� �������������� SSL.

%description devel -l uk
�������� openssl ��� ������ � �����Ʀ������ �� ¦�̦����� �Ц������
������������, �� ���̦����� ������ ˦��˦��� ���������Ʀ����
�������ͦ�, ��������� DES, RC4, RSA �� SSL. ������ ¦�̦����� ��
������ ��� �������� ������� � ������������� SSL.

%package static
Summary:	Static OpenSSL libraries
Summary(pl):	Statyczne wersje bibliotek z OpenSSL
Summary(pt_BR):	Bibliotecas est�ticas para desenvolvimento com openssl
Summary(ru):	����������� ���������� ������������ ��� OpenSSL
Summary(uk):	������Φ ¦�̦����� ������ͦ��� ��� OpenSSL
Group:		Development/Libraries
Requires:	%{name}-devel = %{version}-%{release}

%description static
Static OpenSSL Toolkit libraries.

%description static -l pl
Statyczne wersje bibliotek z OpenSSL.

%description static -l pt_BR
Bibliotecas est�ticas para desenvolvimento com openssl.

%description static -l ru
��������� openssl ��� ������ � ������������� � ����������� ����������,
������� ��������� ��������� ����������������� ����������, ������� DES,
RC4, RSA � SSL. �������� ����������� ���������� ��� ����������
���������� � �������������� OpenSSL.

%description static -l uk
�������� openssl ��� ������ � �����Ʀ������ �� ¦�̦����� �Ц������
������������, �� ���̦����� ������ ˦��˦��� ���������Ʀ����
�������ͦ�, ��������� DES, RC4, RSA �� SSL. ������ ������Φ
¦�̦����� ��� �������� ������� � ������������� SSL.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1

%build
%{__perl} -pi -e 's#%{_prefix}/local/bin/perl#%{__perl}#g' \
	`grep -l -r "%{_prefix}/local/bin/perl" *`

touch Makefile.*

%{__perl} util/perlpath.pl %{__perl}

OPTFLAGS="%{rpmcflags} %{?with_purify:-DPURIFY}"
LDFLAGS="%{rpmldflags}"
export OPTFLAGS LDFLAGS
./Configure \
	--openssldir=%{_var}/lib/%{name} \
	--lib=%{_lib} \
	shared threads \
	enable-mdc2 enable-rc5 \
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

%{__make} -j1 \
	CC="%{__cc}" \
	INSTALLTOP=%{_prefix}

%{__make} -j1 rehash \
	CC="%{__cc}" \
	INSTALLTOP=%{_prefix}

# Conv PODs to man pages. "openssl_" prefix is added to each manpage
# to avoid potential conflicts with others packages.
center="OpenSSL 0.9.7"
rel="OpenSSL 0.9.7"

cd doc/apps || exit 1
%{__perl} -pi -e 's/(\W)((?<!openssl_)\w+)(\(\d\))/$1openssl_$2$3/g; s/openssl_openssl/openssl/g;' *.pod;

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

	%{__perl} -pi -e 's/(\W)((?<!openssl_)\w+)(\(\d\))/$1openssl_$2$3/g; s/openssl_openssl/openssl/g;' *.pod;

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
#%%{__perl} Makefile.PL \
#	INSTALLDIRS=vendor
#%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/%{name},%{_libdir}/%{name}} \
	$RPM_BUILD_ROOT{%{_mandir}/{pl/man1,man{1,3,5,7}},%{_datadir}/ssl} \
	$RPM_BUILD_ROOT%{_pkgconfigdir}

%{__make} install \
	CC="%{__cc}" \
	INSTALLTOP=%{_prefix} \
	INSTALL_PREFIX=$RPM_BUILD_ROOT \
	MANDIR=%{_mandir}

install %{SOURCE1} $RPM_BUILD_ROOT%{_datadir}/ssl/ca-bundle.crt
install libcrypto.a libssl.a $RPM_BUILD_ROOT%{_libdir}
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
install %{SOURCE2} $RPM_BUILD_ROOT%{_mandir}/pl/man1/openssl.1
install %{SOURCE3} $RPM_BUILD_ROOT%{_bindir}/ssl-certificate

%clean
rm -rf $RPM_BUILD_ROOT

%post   -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libcrypto.so.*.*.*
%attr(755,root,root) %{_libdir}/libssl.so.*.*.*
%doc CHANGES CHANGES.SSLeay LICENSE NEWS README doc/*.txt
%doc doc/openssl_button.gif doc/openssl_button.html
%dir %{_libdir}/engines
%attr(755,root,root) %{_libdir}/engines/*.so
%dir %{_var}/lib/%{name}
%dir %{_var}/lib/%{name}/certs
%dir %{_var}/lib/%{name}/private
%dir %{_datadir}/ssl
%verify(not md5 mtime size) %config(noreplace) %{_datadir}/ssl/ca-bundle.crt

%files tools
%defattr(644,root,root,755)
%dir %{_sysconfdir}/%{name}

%verify(not md5 mtime size) %config(noreplace) %{_sysconfdir}/%{name}/openssl.cnf
%verify(not md5 mtime size) %config(noreplace) %{_var}/lib/%{name}/openssl.cnf

%attr(755,root,root) %{_bindir}/%{name}
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
%{_mandir}/man1/openssl_genrsa.1*
%{_mandir}/man1/openssl_nseq.1*
%{_mandir}/man1/openssl_ocsp.1*
%{_mandir}/man1/openssl_passwd.1*
%{_mandir}/man1/openssl_pkcs12.1*
%{_mandir}/man1/openssl_pkcs7.1*
%{_mandir}/man1/openssl_pkcs8.1*
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
%{_mandir}/man1/openssl_verify.1*
%{_mandir}/man1/openssl_version.1*
%{_mandir}/man1/openssl_x509.1*
%{_mandir}/man1/openssl_x509v3_config.1*
%{_mandir}/man5/*.5*
%lang(pl) %{_mandir}/pl/man1/openssl.1*

%files tools-perl
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/%{name}/CA.pl
%attr(755,root,root) %{_libdir}/%{name}/c_rehash
%{_mandir}/man1/openssl_CA.pl.1*

%files devel
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libcrypto.so
%attr(755,root,root) %{_libdir}/libssl.so
%{_includedir}/%{name}
%{_pkgconfigdir}/libcrypto.pc
%{_pkgconfigdir}/libssl.pc
%{_pkgconfigdir}/openssl.pc
%{_mandir}/man3/openssl*.3*
%{_mandir}/man7/*.7*

%files static
%defattr(644,root,root,755)
%{_libdir}/lib*.a
