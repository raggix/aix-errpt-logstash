#!/usr/bin/perl
#===============================================================================
# Script        : errpt2logstash.pl
#
# Description   : Forward (and transform) ERRPT events to a logstash server.
#
# Author        : Ron Wellnitz
#
# Version       : 0.3
#-------------------------------------------------------------------------------
#
# History:
#
# <DATE>        <AUTHOR>        <REASON>
# ----------    -------------- ------------------------------------------------
# 2015-01-26    Ron Wellnitz    initial creation
# 2015-01-28    Ron Wellnitz    Bugfixing, improved argument parsing
# 2015-02-03    Ron Wellnitz    Adding errpt description field
#                               Fixing error_id to hexadecimal integer
# 2015-03-23    Ron Wellnitz    Adjusted comments, small improvements
#
#
#-------------------------------------------------------------------------------
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
# * ------------------------------------------------------------------
# * modify the configuration file -> set logstash server name and port
# * ------------------------------------------------------------------
#
#   odmadd errpt2logstash.add
#
# uninstall:
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
# >logstash_server_name=localhost
# >logstash_server_port=5555
# ># ignore redirected messages from AIX Syslog [MESSAGE REDIRECTED FROM SYSLOG]
# ># usefull if syslog is already sends messages to a logstahs server
# ># 0 = false | 1 = true
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
#   /usr/local/bin/errpt2logstash.pl
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
my $SERVER_ADDR           = "localhost";
my $SERVER_PORT           = "5555";
my $IGNORE_SYSLOG         = 0;

#===============================================================================
# main program
#===============================================================================

# process script arguments $1 - $9
foreach ("errpt_sequence_number", "errpt_error_id", "errpt_class",
         "errpt_type",            "errpt_alert_flags", "errpt_resource_name",
         "errpt_resource_type",   "errpt_resource_class", "errpt_error_label") {

  $ELEMENTS{$_} = ($#ARGV + 1) ? shift : 'unset';
  if(( "$_" eq "errpt_error_id") && ($ELEMENTS{$_} =~ /^0x[0-9a-f]+/)) {
    (my $dummy, $ELEMENTS{$_}) = split(/0X/,uc($ELEMENTS{$_}));
  }
}

# parse configuration file
open(FILE,'<',$CONFIGFILE)
  or die "\nERROR:\tUnable to open configuration file [$CONFIGFILE]: $!\n";
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
close(FILE);

# if set, ignore syslog messages -> script end
if ($IGNORE_SYSLOG && $ELEMENTS{errpt_error_label} eq "SYSLOG") {
  exit(0);
}

# check for misconfigurations (e.g. empty config file)
if(!$SERVER_ADDR || !$SERVER_PORT || $SERVER_PORT !~ /^[0-9]+$/) {
  print "\nERROR:\tInvalid Server configuration in file [$CONFIGFILE]\n";
  print "\tServer: [$SERVER_ADDR]\n\tPort: [$SERVER_PORT]\n";
  exit(1);
}

# read hostname and the full errpt entry (description)
# remove/escape special chars
chomp($ELEMENTS{logsource} = `/usr/bin/hostname -s 2>&1`);

my $DESCRIPTION_FOUND=0;
if ($ELEMENTS{errpt_sequence_number} =~ /^\d+$/) {
  my @ERRPT_OUT = `/usr/bin/errpt -l $ELEMENTS{errpt_sequence_number} -a 2>&1`;
  if($#ERRPT_OUT > 0) {
    foreach(@ERRPT_OUT) {
      chomp($_);
      $_ =~ s/[\t]/\\t/g;
      $_ =~ s/(['"])/\\\$1/g;
      #$_ =~ s/[^a-zA-z0-9:\/+-=?!.,;_#()<> ]/ /g;
      $ELEMENTS{errpt_description} = "$_" if ($DESCRIPTION_FOUND);
      $ELEMENTS{message} .= "$_\\r\\n";
      $DESCRIPTION_FOUND = ($_ =~ /^Description$/) ? 1 : 0;
    }
  }
  else {
    $ELEMENTS{message} .= "sequence number not found\\r\\n";
  }
}
else {
  $ELEMENTS{message} .= "invalid sequence number\\r\\n";
}

# map some errpt identifier to default syslog labels
# errpt_error_label => program
# errpt_class       => facility_label
# errpt_type        => severity_label
if (exists $ERROR_CLASS{$ELEMENTS{errpt_class}}) {
  $ELEMENTS{facility_label} = $ERROR_CLASS{$ELEMENTS{errpt_class}};
}
else {
  $ELEMENTS{facility_label} = $ELEMENTS{errpt_class};
}
if (exists $ERROR_TYPE{$ELEMENTS{errpt_type}}) {
  $ELEMENTS{severity_label} = $ERROR_TYPE{$ELEMENTS{errpt_type}};
}
else {
  $ELEMENTS{severity_label} = $ELEMENTS{errpt_type};
}
$ELEMENTS{program} = $ELEMENTS{errpt_error_label};

# open tcp connection to the logstash server
my $SOCKET = IO::Socket::INET->new(Proto => "tcp", Timeout => "2",
  PeerAddr => $SERVER_ADDR, PeerPort => $SERVER_PORT)
  or die "\nERROR:\tUnable to connect to [${SERVER_ADDR}:${SERVER_PORT}]: $!\n";

# build and send JSON string
my $JSON_STRING = "{";
for $ELEMENT ( sort keys %ELEMENTS ) {
  $JSON_STRING .= "\"$ELEMENT\": \"$ELEMENTS{$ELEMENT}\"," ;
}
$JSON_STRING  = substr($JSON_STRING,0,(length($JSON_STRING)-1));
$JSON_STRING .= "}\n";
print $SOCKET $JSON_STRING;

# close connection and exit
$SOCKET->close();
exit(0); 
