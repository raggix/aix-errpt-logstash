# Build RPM (example)
prepare source direcotory
```
~/errpt2logstash
~/errpt2logstash/errpt2logstash.conf
~/errpt2logstash/errpt2logstash.pl 
```
create tar.gz-file
```
tar -cf errpt2logstash-0.3.tar errpt2logstash
gzip errpt2logstash-0.3.tar 
cp errpt2logstash-0.3.tar.gz /opt/freeware/src/packages/SOURCES 
```
build RPM
```
rpm -ba errpt2logstash.spec 
```
install RPM
```
cp /opt/freeware/src/packages/RPMS/noarch/errpt2logstash*.ppc.rpm .
rpm -iv errpt2logstash*.ppc.rpm 
```
