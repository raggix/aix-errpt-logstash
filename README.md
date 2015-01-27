# errpt2logstash
Send events from AIX error report (errpt) to a logstash server

# install
```
cp errpt2logstash.pl /usr/local/bin/errpt2logstash.pl
chown root:system /usr/local/bin/errpt2logstash.pl
chmod 750 /usr/local/bin/errpt2logstash.pl

cp errpt2logstash.conf /etc/errpt2logstash.conf
chown root:system /etc/errpt2logstash.conf
chmod 660 /etc/errpt2logstash.conf
```
**modify the configuration file (errpt2logstash.conf) -> add your logstash server and port**
```
odmadd errpt2logstash.add
```
# configure logstash
```
input {
   tcp {
     port => 5555
     type => errpt
     codec => json
   }
}
```
#test
**Logstash server**
```
/opt/logstash/bin/logstash agent -e 'input {tcp { port => "5555" codec => json }} output { stdout { codec => rubydebug }}'
```
***AIX Server***
```
errlogger "Hello World"
logger -plocal0.crit "Hello World"
```
# deinstall
```
odmdelete -q 'en_name=errpt2logstash' -o errnotify
rm /usr/local/bin/errpt2logstash.pl
rm /etc/errpt2logstash.conf
```
