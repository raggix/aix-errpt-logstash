# errpt2logstash
Send events from AIX error report (errpt) to a logstash server
# install
```
cp errpt2logstash.pl /usr/local/bin/errpt2logstash.pl
chown root:system /usr/local/bin/errpt2logstash.pl
chmod 750 /usr/local/bin/errpt2logstash.pl
```
**customize the configuration file errpt2logstash.conf**
```
cp errpt2logstash.conf /etc/errpt2logstash.conf
chown root:system /etc/errpt2logstash.conf
chmod 660 /etc/errpt2logstash.conf

odmadd errpt2logstash.add
```
# example logstash input configuration
```
input {
   tcp {
     port => 5555
     type => errpt
     codec => json
   }
}
```
# example logstash filter configuration
```
filter {
  #
  # AIX ERRPT
  # define and handle critical messages
  #
  if [type] == "errpt" {
    if [errpt_error_class] == "H" or [facility_label] == "Hardware" {
      if [errpt_error_type] == "PERM" or [severity_label] == "Permanent" {
        #
        # PERM H exclude list
        #
        # 07A33B6A SC_TAPE_ERR4        PERM H  TAPE DRIVE FAILURE
        # 4865FA9B TAPE_ERR1           PERM H  TAPE OPERATION ERROR
        # 68C66836 SC_TAPE_ERR1        PERM H  TAPE OPERATION ERROR
        # E1D8D4A4 SC_TAPE_ERR2        PERM H  TAPE DRIVE FAILURE
        # BFE4C025 SCAN_ERROR_CHRP     PERM H  UNDETERMINED ERROR
        #
        if [errpt_error_id] not in ["68C66836", "07A33B6A", "E1D8D4A4", "4865FA9B", "BFE4C025"] {
          mutate {
            add_tag => [ "critical" ]
          }
        }
      }
    }
    #
    # overall include list
    #
    # 0975DD6C KERNEL_ABEND        PERM S  KERNEL ABNORMALLY TERMINATED
    # 4B97B439 J2_METADATA_CORRUPT UNKN U  FILE SYSTEM CORRUPTION
    # AE3E3FAD J2_FSCK_INFO        INFO O  FSCK FOUND ERRORS
    # B6DB68E0 J2_FSCK_REQUIRED    INFO O  FILE SYSTEM RECOVERY REQUIRED
    # C4C3339D LGPG_FREED          INFO S  ONE OR MORE LARGE PAGES HAS BEEN CONVERT
    # C5C09FFA PGSP_KILL           PERM S  SOFTWARE PROGRAM ABNORMALLY TERMINATED
    # FE2DEE00 AIXIF_ARP_DUP_ADDR  PERM S  DUPLICATE IP ADDRESS DETECTED IN THE NET
    #
    if [errpt_error_id] in ["0975DD6C", "4B97B439", "AE3E3FAD", "B6DB68E0", "C4C3339D", "C5C09FFA", "FE2DEE00"] {
      mutate {
        add_tag => [ "critical" ]
      }
    }
    #
    # Forward
    #
    if "critical" in [tags] {
      throttle {
        # max. one alert within five minutes per host and errpt identifier
        before_count => -1
        after_count => 1
        key => "%{logsource}:%{errpt_error_id}"
        period => 300
        add_tag => [ "throttled" ]
      }
      if "throttled" not in [tags] {
        email {
         from => "logstash@server.de"
         subject => "CRITICAL: %{logsource} - %{errpt_description}"
         to => "admin@server.de"
         via => "sendmail"
         body => "%{message}"
         options => { "location" => "/usr/sbin/sendmail" }
        }
      }
    }
  }
}
```
# testing
**Logstash server**
```
/opt/logstash/bin/logstash agent -e 'input {tcp { port => 5555 codec => json }} output { stdout { codec => rubydebug }}'
```
***AIX server***
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
