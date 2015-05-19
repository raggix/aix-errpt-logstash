Name:      errpt2logstash
Summary:   errpt2logstash
Version:   0.3
Release:   1
URL:       https://github.com/raggix/errpt2logstash
License:   none
Group:     System/Base
BuildRoot: /opt/freeware/src/packages/BUILD/%{name}
Packager:  Ron Wellnitz
Requires:  /usr/bin/perl
#Requires: /usr/bin/perl, /usr/bin/odmadd, /usr/bin/odmdelete
Source:    %{name}-%{version}.tar.gz
BuildArch: ppc

%description
Forward (and transform) ERRPT events to a logstash server.

%pre
# If the first argument to %pre is 1, the RPM operation is an initial installation.
# If the argument to %pre is 2, the operation is an upgrade from an existing version to a new one.
if [[ -f /etc/errpt2logstash.conf ]];then
  mv /etc/errpt2logstash.conf /etc/errpt2logstash.conf.rpmsave
fi

%prep

%setup -n %{name}

# the set up macro unpacks the source bundle and changes in to the represented by
# %{name} which in this case would be my_maintenance_scripts. So your source bundle
# needs to have a top level directory inside called my_maintenance _scripts

%build
# this section is empty for this example as we're not actually building anything

%install
# create directories where the files will be located

if [[ -f /usr/local/bin/errpt2logstash.pl ]];then
  rm -f /usr/local/bin/errpt2logstash.pl
fi
if [[ -f /etc/errpt2logstash.conf ]];then
  mv /etc/errpt2logstash.conf /etc/errpt2logstash.conf.rpmsave
fi

mkdir -p ${RPM_BUILD_ROOT}/usr/local/bin
mkdir -p ${RPM_BUILD_ROOT}/etc
mv ${RPM_BUILD_ROOT}/errpt2logstash.pl ${RPM_BUILD_ROOT}/usr/local/bin
mv ${RPM_BUILD_ROOT}/errpt2logstash.conf ${RPM_BUILD_ROOT}/etc

install -c /usr/local/bin -M 0750 ${RPM_BUILD_ROOT}/usr/local/bin/errpt2logstash.pl
install -c /etc -M 0660 ${RPM_BUILD_ROOT}/etc/errpt2logstash.conf

%clean
cd `dirname $RPM_BUILD_ROOT`
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
# list files owned by the package here
%defattr(-,root,root)
%attr(750,root,root) /usr/local/bin/errpt2logstash.pl
%attr(660,root,root) /etc/errpt2logstash.conf

%post
# handle Upgrade -> keep current Configuration
if [[ $1 -eq 2 && -f /etc/errpt2logstash.conf.rpmsave ]];then
  mv /etc/errpt2logstash.conf /etc/errpt2logstash.conf.rpmnew
  mv /etc/errpt2logstash.conf.rpmsave /etc/errpt2logstash.conf
fi

# the post section is where you can run commands after the rpm is installed.
/usr/bin/odmdelete -q 'en_name=errpt2logstash' -o errnotify >/dev/null 2>&1
/usr/bin/odmadd <<EOF
errnotify:
en_pid = 0
en_name = "errpt2logstash"
en_persistenceflg = 1
en_method = "/usr/local/bin/errpt2logstash.pl \$1 \$2 \$3 \$4 \$4 \$6 \$7 \$8 \$9"
EOF

%postun
# If the first argument to %preun and %postun is 1, the action is an upgrade.
# If the first argument to %preun and %postun is 0, the action is uninstallation.
if [ "$1" = "0" ];then
  /usr/bin/odmdelete -q 'en_name=errpt2logstash' -o errnotify >/dev/null 2>&1
fi

%changelog
* Mon Mar 23 2015 Ron Wellnitz
- 0.2 Second Release
- 0.3 Adjusted comments, small improvements 
