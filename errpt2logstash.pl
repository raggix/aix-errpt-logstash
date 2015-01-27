
#!/usr/bin/perl
#===============================================================================
# Script        : errpt2logstash.pl
#
# Description   : Forward (and transform) ERRPT events to a logstash server.
#
# Version       : 0.1
#-------------------------------------------------------------------------------
#
# History:
#
# <DATE>        <AUTHOR>        <REASON>
# ----------    -------------- ------------------------------------------------
# 2015-01-26    Ron Wellnitz    initial creation
#
#
# ToDo:
#
# - remove duplicate information from 'errpt -a' output?
# - build RPM
#
#-------------------------------------------------------------------------------
# install:
#   cp errpt2logstash.pl /usr/local/bin/errpt2logstash.pl
#   chown root:system /usr/local/bin/errpt2logstash.pl
#   chmod 750 /usr/local/bin/errpt2logstash.pl
#
#   cp errpt2logstash.conf /etc/errpt2logstash.conf
#   chown root:system /etc/errpt2logstash.conf
#   chmod 660 /etc/errpt2logstash.conf
#
# *** modify the configuration file -> add your logstash server and port ***
#
#   odmadd errpt2logstash.add
#
# deinstall:
#   odmdelete -q 'en_name=errpt2logstash' -o errnotify
#   rm /usr/local/bin/errpt2logstash.pl
#   rm /etc/errpt2logstash.conf
#
#-------------------------------------------------------------------------------
# errnotify argument description
#-------------------------------------------------------------------------------
# $1    Sequence number from the error log entry
# $2    Error ID from the error log entry
# $3    Class from the error log entry
# $4    Type from the error log entry
# $5    Alert flags value from the error log entry
# $6    Resource name from the error log entry
# $7    Resource type from the error log entry
# $8    Resource class from the error log entry
# $9    Error label from the error log entry
#
#-------------------------------------------------------------------------------
# [Example] errpt2logstash.add
#-------------------------------------------------------------------------------
# >errnotify:
# >en_pid = 0
# >en_name = "errpt2logstash"
# >en_persistenceflg = 1
# >en_method = "/usr/local/bin/errpt2logstash.pl $1 $2 $3 $4 $4 $6 $7 $8 $9"
#
#-------------------------------------------------------------------------------
# [Example] /etc/errpt2logstash.conf
#-------------------------------------------------------------------------------
# ># remote logstash server name
# >logstash_server_name=localhost
# >#
# ># remote logstash server port
# >logstash_server_port=5555
# >#
# ># ignore messages from AIX Syslog, e.g. they already/directly forwarded
# ># from Syslog-Daemon to the logstash server -> avoid duplicate log entrys
# ># 0 = false
# ># 1 = true
# >ignore_syslog_messages=0
#
#-------------------------------------------------------------------------------
# [Example] logstash-input.conf
#-------------------------------------------------------------------------------
# >input {
# >  tcp {
# >    port => 5555
# >    type => errpt
# >    codec => json
# >  }
# >}
#-------------------------------------------------------------------------------
# [Test]
#-------------------------------------------------------------------------------
# Logstash Server:
#   /opt/logstash/bin/logstash agent -e 'input {tcp { port => "5555"
#     codec => json }} output { stdout { codec => rubydebug }}'
#
# AIX Server:
#   errlogger "Hello World"
#   logger -plocal0.crit "Hello World"
#-------------------------------------------------------------------------------
#===============================================================================
use strict;
use warnings;
use POSIX;
use Socket;
use IO::Socket;
use IO::Handle;

# turn on autoflush
$|++;

#===============================================================================
# user variables
#===============================================================================

# logstash server configuration file
my $CONFIGFILE = "/etc/errpt2logstash.conf";

#===============================================================================
# script variables
#===============================================================================

# errnotify arguments
my $ELEMENT;
my %ELEMENTS;
$ELEMENTS{sequence_number} = shift;
$ELEMENTS{error_id}        = shift;
$ELEMENTS{error_class}     = shift;
$ELEMENTS{error_type}      = shift;
$ELEMENTS{alert_flags}     = shift;
$ELEMENTS{resource_name}   = shift;
$ELEMENTS{resource_type}   = shift;
$ELEMENTS{resource_class}  = shift;
$ELEMENTS{error_label}     = shift;

# errpt output
$ELEMENTS{message}         = "";

# type of error
my %ERROR_TYPE;
$ERROR_TYPE{PEND}         = "Pending";
$ERROR_TYPE{PERF}         = "Performance";
$ERROR_TYPE{PERM}         = "Permanent";
$ERROR_TYPE{TEMP}         = "Temporary";
$ERROR_TYPE{INFO}         = "Informational";
$ERROR_TYPE{UNKN}         = "Unknown";

# class of error
my %ERROR_CLASS;
$ERROR_CLASS{H}           = "Hardware";
$ERROR_CLASS{S}           = "Software";
$ERROR_CLASS{O}           = "Operator Notice";
$ERROR_CLASS{U}           = "Undetermined";

# initial user configuration variables
my $SERVER_ADDR            = "";
my $SERVER_PORT            = "";
my $IGNORE_SYSLOG          = 0;

#===============================================================================
# main program
#===============================================================================

#
# - if set, ignore syslog messages
#
if ($IGNORE_SYSLOG && $ELEMENTS{error_label} == "SYSLOG") {
  exit(0);
}

#
# - parse configuration file
#
open(FILE, $CONFIGFILE)
  or die "\nERROR: Unable to open config file: $CONFIGFILE!\n";
while(<FILE>) {
   chomp($_);
   if ($_ =~ /logstash_server_name/) {
      (my $dummy,$SERVER_ADDR)   = split(/=/,$_);
   }
   if ($_ =~ /logstash_server_port/) {
      (my $dummy,$SERVER_PORT)   = split(/=/,$_);
   }
   if ($_ =~ /ignore_syslog_messages/) {
      (my $dummy,$IGNORE_SYSLOG) = split(/=/,$_);
   }
}
if(!$SERVER_ADDR || !$SERVER_PORT) {
  print "\nERROR: Invalid server: $SERVER_ADDR or port: $SERVER_PORT!\n";
  exit(1);
}

#
# - read hostname
# - read the errpt entry
# - remove/escape special chars
#
chomp($ELEMENTS{logsource} = `/usr/bin/hostname -s 2>&1`);
my @ERRPT_OUT = `/usr/bin/errpt -l $ELEMENTS{sequence_number} -a 2>&1`;
foreach(@ERRPT_OUT) {
 chomp($_);
 $_ =~ s/[\t]/\\t/g;
 $_ =~ s/(['"])/\\\$1/g;
 #$_ =~ s/[^a-zA-z0-9:\/+-=?!.,;_#()<> ]/ /g;
 $ELEMENTS{message} .= "$_\\r\\n";
}

#
# - do some mapping for a better standard syslog matching
#
if (exists $ERROR_CLASS{$ELEMENTS{error_class}}) {
  $ELEMENTS{facility_label} = $ERROR_CLASS{$ELEMENTS{error_class}};
} else {
  $ELEMENTS{facility_label} = $ELEMENTS{error_class};
}
if (exists $ERROR_TYPE{$ELEMENTS{error_type}}) {
  $ELEMENTS{severity_label} = $ERROR_TYPE{$ELEMENTS{error_type}};
} else {
  $ELEMENTS{severity_label} = $ELEMENTS{error_type};
}
$ELEMENTS{program} = $ELEMENTS{error_label};

#
# - open tcp connection to logstash server
# - build and send JSON string
# - close connection and exit
#
my $SOCKET = IO::Socket::INET->new(Proto => "tcp", Timeout => "2",
  PeerAddr => $SERVER_ADDR, PeerPort => $SERVER_PORT)
  or die "\nUnable to connect to ${SERVER_ADDR}:${SERVER_PORT}!\n\n";

my $JSON_STRING = "{";
for $ELEMENT ( sort keys %ELEMENTS ) {
  $JSON_STRING .= "\"$ELEMENT\": \"$ELEMENTS{$ELEMENT}\"," ;
}
$JSON_STRING = substr($JSON_STRING,0,(length($JSON_STRING)-1));
$JSON_STRING .= "}\n";

print $SOCKET $JSON_STRING;
$SOCKET->close();
exit(0);
