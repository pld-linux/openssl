# conditional build:
# _without_embed - don't build uClibc version
%include	/usr/lib/rpm/macros.perl
Summary:	OpenSSL Toolkit libraries for the "Secure Sockets Layer" (SSL v2/v3)
Summary(de):	Secure Sockets Layer (SSL)-Kommunikationslibrary
Summary(fr):	Utilitaires de communication SSL (Secure Sockets Layer)
Name:		openssl
Version:	0.9.6c
Release:	1
License:	Apache-style License
Vendor:		The OpenSSL Project
Group:		Libraries
Group(de):	Libraries
Group(es):	Bibliotecas
Group(fr):	Librairies
Group(pl):	Biblioteki
Group(pt_BR):	Bibliotecas
Group(ru):	‚…¬Ã…œ‘≈À…
Group(uk):	‚¶¬Ã¶œ‘≈À…
Source0:	ftp://ftp.openssl.org/source/%{name}-%{version}.tar.gz
Patch0:		%{name}-alpha-ccc.patch
# patch1 is only for 0.9.6a version. This version isn't binary
# compatibile with 0.9.6 but have this same soname.
Patch1:		%{name}-soname.patch
Patch2:		%{name}-optflags.patch
Patch3:		%{name}-nocrypt.patch
BuildRequires:	perl-devel >= 5.6.1
BuildRequires:	textutils
%if %{!?_without_embed:1}%{?_without_embed:0}
BuildRequires:	uClibc-devel
BuildRequires:	uClibc-static
%endif
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Obsoletes:	SSLeay
Obsoletes:	SSLeay-devel
Obsoletes:	SSLeay-perl
Obsoletes:	libopenssl0

%define embed_path	/usr/lib/embed
%define embed_cc	%{_arch}-uclibc-cc
%define embed_cflags	%{rpmcflags} -Os
%define uclibc_prefix	/usr/%{_arch}-linux-uclibc

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
Openssl enth‰lt das OpenSSL Zertifikatsmanagementtool und shared
libraries, die verschiedene Verschl¸sselungs- und
Entschl¸sselungsalgorithmen und
- -protokolle, wie DES, RC4, RSA und SSL zur Verf¸gung stellen.

%description -l fr
OpenSSL est un outiil de gestion des certificats et les librairies
partagees qui fournit plusieurs protocoles et algorithmes de
codage/decodage, incluant DES, RC4, RSA et SSL.

%package tools
Summary:	OpenSSL command line tool and utilities
Group:		Applications/Communications
Group(de):	Applikationen/Kommunikation
Group(pl):	Aplikacje/Komunikacja
Requires:	%{name} = %{version}

%description tools
The OpenSSL Toolkit cmdline tool openssl and utility scripts.

%package tools-perl
Summary:	OpenSSL utilities written in Perl
Group:		Applications/Communications
Group(de):	Applikationen/Kommunikation
Group(fr):	Utilitaires
Group(pl):	Aplikacje/Komunikacja
Requires:	%{name} = %{version}

%description tools-perl
OpenSSL Toolkit tools written in Perl.

%package devel
Summary:	Development part of OpenSSL Toolkit libraries
Summary(de):	Secure Sockets Layer Kommunikationslibrary: statische libraries+header
Summary(fr):	Librairies statiques, headers et utilitaires pour communication SSL
Summary(pl):	CzÍ∂Ê bibiloteki OpenSSL przeznaczona dla programistÛw
Group:		Development/Libraries
Group(de):	Entwicklung/Libraries
Group(es):	Desarrollo/Bibliotecas
Group(fr):	Development/Librairies
Group(pl):	Programowanie/Biblioteki
Group(pt_BR):	Desenvolvimento/Bibliotecas
Group(ru):	Ú¡⁄“¡¬œ‘À¡/‚…¬Ã…œ‘≈À…
Group(uk):	Úœ⁄“œ¬À¡/‚¶¬Ã¶œ‘≈À…
Requires:	%{name} = %{version}
Obsoletes:	libopenssl0-devel

%description devel
Development part of OpenSSL library.

%description devel -l pl
CzÍ∂Ê bibiloteki OpenSSL przeznaczona dla programistÛw.

%package devel-embed
Summary:	Development part of OpenSSL Toolkit embedded libraries
Summary(pl):	CzÍ∂Ê bibiloteki OpenSSL przeznaczona dla aplikacji wbudowanych
Group:		Development/Libraries
Group(de):	Entwicklung/Libraries
Group(es):	Desarrollo/Bibliotecas
Group(fr):	Development/Librairies
Group(pl):	Programowanie/Biblioteki
Group(pt_BR):	Desenvolvimento/Bibliotecas
Group(ru):	Ú¡⁄“¡¬œ‘À¡/‚…¬Ã…œ‘≈À…
Group(uk):	Úœ⁄“œ¬À¡/‚¶¬Ã¶œ‘≈À…
Requires:	%{name} = %{version}

%description devel-embed
Development part of OpenSSL library for embedded applications.

%description -l pl devel-embed
CzÍ∂Ê bibiloteki OpenSSL przeznaczona dla programistÛw aplikacji
wbudowanych.

%package static
Summary:	Static OpenSSL libraries
Summary(pl):	Statyczne wersje bibliotek z OpenSSL
Group:		Development/Libraries
Group(de):	Entwicklung/Libraries
Group(es):	Desarrollo/Bibliotecas
Group(fr):	Development/Librairies
Group(pl):	Programowanie/Biblioteki
Group(pt_BR):	Desenvolvimento/Bibliotecas
Group(ru):	Ú¡⁄“¡¬œ‘À¡/‚…¬Ã…œ‘≈À…
Group(uk):	Úœ⁄“œ¬À¡/‚¶¬Ã¶œ‘≈À…
Requires:	%{name}-devel = %{version}

%description static
Static OpenSSL Toolkit libraries.

%description static -l pl
Statyczne wersje bibliotek z OpenSSL.

%prep
%setup -q 
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
for f in ` grep -r "/usr/local/bin/perl" . | cut -d":" -f1`; do
	perl -pi -e 's#/usr/local/bin/perl#%{_bindir}/perl#g' $f
done

touch Makefile.*

perl util/perlpath.pl %{_bindir}/perl

OPTFLAGS="%{rpmcflags}"
export OPTFLAGS
%ifarch i386 i486
./Configure --openssldir=%{_var}/lib/%{name} linux-elf shared 386
%endif
%ifarch i586 i686
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

%if %{!?_without_embed:1}%{?_without_embed:0}
%{__make} CC=%{embed_cc}
%{__make} rehash CC=%{embed_cc}
for f in RSAglue crypto ssl ; do
	mv -f lib$f.a lib$f.a-embed
done
%{__make} clean
%endif

%{__make}
%{__make} rehash

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
	   $RPM_BUILD_ROOT%{_mandir}/man{1,3,5,7}

%{__make} install \
	INSTALLTOP=%{_prefix} \
	INSTALL_PREFIX=$RPM_BUILD_ROOT

install libRSAglue.a libcrypto.a libssl.a 	$RPM_BUILD_ROOT%{_libdir}
install lib*.so.*.* 	$RPM_BUILD_ROOT%{_libdir}
ln -sf libcrypto.so.*.* $RPM_BUILD_ROOT%{_libdir}/libcrypto.so
ln -sf libssl.so.*.* $RPM_BUILD_ROOT%{_libdir}/libssl.so

mv -f $RPM_BUILD_ROOT%{_var}/lib/%{name}/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/%{name}
ln -s %{_sysconfdir}/%{name}/openssl.cnf \
	$RPM_BUILD_ROOT%{_var}/lib/%{name}/%{name}.cnf

mv -f $RPM_BUILD_ROOT%{_var}/lib/%{name}/misc/*  $RPM_BUILD_ROOT%{_libdir}/%{name}
rm -rf $RPM_BUILD_ROOT%{_var}/lib/%{name}/misc

mv -f $RPM_BUILD_ROOT%{_bindir}/c_rehash $RPM_BUILD_ROOT%{_libdir}/%{name}

find $RPM_BUILD_ROOT%{_mandir} -type f | xargs rm -f
install doc/apps/*.1 $RPM_BUILD_ROOT%{_mandir}/man1
install doc/apps/*.5 $RPM_BUILD_ROOT%{_mandir}/man5
install doc/ssl/*.3 doc/crypto/*.3 $RPM_BUILD_ROOT%{_mandir}/man3
install doc/crypto/*.7 $RPM_BUILD_ROOT%{_mandir}/man7

%if %{!?_without_embed:1}%{?_without_embed:0}
install -d $RPM_BUILD_ROOT%{uclibc_prefix}/{include,lib}
for f in RSAglue crypto ssl ; do
	install lib$f.a-embed $RPM_BUILD_ROOT%{uclibc_prefix}/lib/lib$f.a
done
cp -a $RPM_BUILD_ROOT%{_includedir}/%{name} \
	$RPM_BUILD_ROOT%{uclibc_prefix}/include
%endif

gzip -9nf CHANGES CHANGES.SSLeay LICENSE NEWS README doc/*.txt

%post   -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/lib*.so.*.*
%doc {CHANGES,CHANGES.SSLeay,LICENSE,NEWS,README}.gz
%doc doc/*.txt.gz doc/openssl_button.gif doc/openssl_button.html

%files tools
%defattr(644,root,root,755)
%dir %{_sysconfdir}/%{name}
%dir %{_var}/lib/%{name}
%dir %{_var}/lib/%{name}/private
%dir %{_var}/lib/%{name}/certs
%verify(not md5 size mtime) %config(noreplace) %{_sysconfdir}/%{name}/openssl.cnf
%verify(not md5 size mtime) %config(noreplace) %{_var}/lib/%{name}/openssl.cnf

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

%if %{!?_without_embed:1}%{?_without_embed:0}
%files devel-embed
%defattr(644,root,root,755)
%{uclibc_prefix}/lib/*
%{uclibc_prefix}/include/%{name}
%endif

%files static
%defattr(644,root,root,755)
%{_libdir}/lib*.a
