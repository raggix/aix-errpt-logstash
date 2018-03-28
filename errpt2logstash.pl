#!/usr/bin/perl
#===============================================================================
# Script        : errpt2logstash.pl
#
# Description   : Forward (and transform) ERRPT events to a logstash server.
#
# Author        : Ron Wellnitz
#
# Version       : 0.5
#-------------------------------------------------------------------------------
#
# History:
#
# <DATE>        <AUTHOR>        <REASON>
# ----------    --------------  ------------------------------------------------
# 2015-01-26    Ron Wellnitz    initial creation
# 2015-01-28    Ron Wellnitz    Bugfixing, improved argument parsing
# 2015-02-03    Ron Wellnitz    Adding errpt description field
#                               Fixing error_id to hexadecimal integer
# 2015-03-23    Ron Wellnitz    Adjusted comments, small improvements
# 2015-09-18    Ron Wellnitz    Add logfile handling
# 2018-02-21    Ron Wellnitz    Decompose a forwarded syslog message and send
#                               the original values for e.g program and message
#
#-------------------------------------------------------------------------------
#
#===============================================================================
use strict;
use warnings;
use POSIX;
use Socket;
use IO::Socket;
use IO::Handle;
use Switch;

# turn on autoflush
$|++;

#===============================================================================
# user variables
#===============================================================================

my $CONFIGFILE = "/etc/errpt2logstash.conf";
my $LOGFILE = "/var/log/errpt2logstash.log";
my $MAXLOGCOUNT = 2000;

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

# syslog specific, in case syslog messages are forwarded
my @SEVERITY_LABEL;
$SEVERITY_LABEL[0] = "emerg";
$SEVERITY_LABEL[1] = "alert";
$SEVERITY_LABEL[2] = "crit";
$SEVERITY_LABEL[3] = "err";
$SEVERITY_LABEL[4] = "warning";
$SEVERITY_LABEL[5] = "notice";
$SEVERITY_LABEL[6] = "info";
$SEVERITY_LABEL[7] = "debug";

my @FACILITY_LABEL;
$FACILITY_LABEL[0]  = "kern";
$FACILITY_LABEL[1]  = "user";
$FACILITY_LABEL[2]  = "mail";
$FACILITY_LABEL[3]  = "daemon";
$FACILITY_LABEL[4]  = "auth";
$FACILITY_LABEL[5]  = "syslog";
$FACILITY_LABEL[6]  = "lpr";
$FACILITY_LABEL[7]  = "news";
$FACILITY_LABEL[8]  = "uucp";
$FACILITY_LABEL[9]  = "clock";
$FACILITY_LABEL[10] = "authpriv";
$FACILITY_LABEL[11] = "ftp";
$FACILITY_LABEL[12] = "ntp";
$FACILITY_LABEL[13] = "audit";
$FACILITY_LABEL[14] = "alert";
$FACILITY_LABEL[15] = "cron";
$FACILITY_LABEL[16] = "local0";
$FACILITY_LABEL[17] = "local1";
$FACILITY_LABEL[18] = "local2";
$FACILITY_LABEL[19] = "local3";
$FACILITY_LABEL[20] = "local4";
$FACILITY_LABEL[21] = "local5";
$FACILITY_LABEL[22] = "local6";
$FACILITY_LABEL[23] = "local7";

# initial user configuration variables
my $SERVER_ADDR           = "localhost";
my $SERVER_PORT           = "5555";
my $IGNORE_SYSLOG         = 0;
my $VERBOSE               = 1;

# logfile switch
my $LOG_ENABLED           = 1;

#===============================================================================
# functions
#===============================================================================

# handle output to STDOUT and logfile
sub message_handler {
  my $TYPE = shift;
  my $MESSAGE = shift;
  my $TIMESTAMP = strftime "%x %X", localtime;
  printf LOGF "[$TIMESTAMP] %-10s $MESSAGE\n", "[$TYPE]" if $LOG_ENABLED;
  switch($TYPE) {
    case "ERROR" {
      print STDERR "\n$TYPE: $MESSAGE\n\n";
      close(LOGF) if $LOG_ENABLED;
      exit(1);
    }
    case /INFO|WARNING/ {
      print STDOUT "\n$TYPE: $MESSAGE\n\n";
    }
    else {
      print STDOUT "\n$MESSAGE\n\n";
    }
  }
}

#===============================================================================
# main program
#===============================================================================

#
# process script arguments $1 - $9
#
foreach ("errpt_sequence_number", "errpt_error_id",       "errpt_class",
         "errpt_type",            "errpt_alert_flags",    "errpt_resource_name",
         "errpt_resource_type",   "errpt_resource_class", "errpt_error_label") {

  $ELEMENTS{$_} = ($#ARGV + 1) ? shift : 'unset';
  if(( "$_" eq "errpt_error_id") && ($ELEMENTS{$_} =~ /^0x[0-9a-f]+/)) {
    (my $dummy, $ELEMENTS{$_}) = split(/0X/,uc($ELEMENTS{$_}),2);
  }
}
#
# touch logfile if necessary
# if logfile is not accessable go ahead without logging
#
if( ! -f $LOGFILE) {
  if(open(LOGF,'>',"$LOGFILE")) {
    close(LOGF);
  } else {
    $LOG_ENABLED = 0;
    message_handler("WARNING","Unable to open Logfile [$LOGFILE]: $!");
  }
}
#
# logfile handling incl. cleanup
#
if($LOG_ENABLED) {
  if(open(LOGF,'<',"$LOGFILE")) {
    flock(LOGF, 1);
    my @LOGFA = <LOGF>;
    close(LOGF);

    if($#LOGFA > $MAXLOGCOUNT) {
      # if max is reached the content of logfile will reduced to the half of max - avoid cleanup every call
      if(open(LOGF,'+<',"$LOGFILE")) {
        flock(LOGF, 2);
        # clear file
        seek(LOGF, 0, 0);
        truncate(LOGF, 0);
        # print last half of old content to file
        print LOGF @LOGFA[floor($#LOGFA/2)..$#LOGFA];
      } else {
        $LOG_ENABLED = 0;
        message_handler("WARNING","Unable to open Logfile [$LOGFILE]: $!");
      }
    } else {
      # just append to logfile
      undef @LOGFA;
      if(!open(LOGF,'>>',"$LOGFILE")) {
        $LOG_ENABLED = 0;
        message_handler("WARNING","Unable to open Logfile [$LOGFILE]: $!");
      }
    }
  } else {
    $LOG_ENABLED = 0;
    message_handler("WARNING","Unable to open Logfile [$LOGFILE]: $!");
  }
}
#
# parse configuration file
#
open(FILE,'<',"$CONFIGFILE")
  or message_handler("ERROR","Unable to open configuration file [$CONFIGFILE]: $!");

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
   if ($_ =~ /verbose_logging/) {
      (my $dummy,$VERBOSE) = split(/=/,$_);
   }
}
close(FILE);
#
# check for misconfigurations (e.g. empty config file)
#
if(!$SERVER_ADDR || !$SERVER_PORT || $SERVER_PORT !~ /^[0-9]+$/) {
  message_handler("ERROR", "Invalid Server [$SERVER_ADDR] and/or Port [$SERVER_PORT] in configuration file [$CONFIGFILE]!");
}
if($IGNORE_SYSLOG !~ /^[0-1]$/) {
  message_handler("ERROR", "Invalid value [$IGNORE_SYSLOG] for <ignore_syslog_messages> in configuration file [$CONFIGFILE]!");
}
if($VERBOSE !~ /^[0-1]$/) {
  message_handler("ERROR", "Invalid value [$VERBOSE] for <verbose_logging> in configuration file [$CONFIGFILE]!");
}
#
# if this is a forwarded syslog message and "ignore syslog messages" is true this script ends
#
if ($IGNORE_SYSLOG && $ELEMENTS{errpt_error_label} eq "SYSLOG") {
  close(LOGF);
  exit(0);
}
#
# read hostname and the full errpt entry (description)
# remove/escape special chars
#
chomp($ELEMENTS{logsource} = `/usr/bin/hostname -s 2>&1`);
my $DESCRIPTION_FOUND=0;
my $SYSLOG_MESSAGE_FOUND=0;
my $SYSLOG_MESSAGE="";
if ($ELEMENTS{errpt_sequence_number} =~ /^\d+$/) {
  my @ERRPT_OUT = `/usr/bin/errpt -l $ELEMENTS{errpt_sequence_number} -a 2>&1`;
  if($#ERRPT_OUT > 0) {
    foreach(@ERRPT_OUT) {
      chomp($_);
      $_ =~ s/[\t]/\\t/g;
      $_ =~ s/['"]//g;
      #$_ =~ s/(['"])/\\$1/g; --> escaping not work :/
      #$_ =~ s/[^a-zA-z0-9:\/+-=?!.,;_#()<> ]/ /g;
      $SYSLOG_MESSAGE = $_ if ($SYSLOG_MESSAGE_FOUND);
      $ELEMENTS{errpt_description} = $_ if ($DESCRIPTION_FOUND);
      $ELEMENTS{message} .= "$_\\r\\n";
      $DESCRIPTION_FOUND = ($_ =~ /^Description$/) ? 1 : 0;
      $SYSLOG_MESSAGE_FOUND = ($_ =~ /^SYSLOG MESSAGE$/) ? 1 : 0;
      last if ($_ =~ /^ADDITIONAL INFORMATION$/);
    }
  }
  else {
    $ELEMENTS{message} .= "sequence number not found\\r\\n";
  }
}
else {
  $ELEMENTS{message} .= "invalid sequence number\\r\\n";
}
#
# map some errpt identifier to default syslog labels
# errpt_error_label => program
# errpt_class       => facility_label
# errpt_type        => severity_label
#
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
#
# if a forewarded syslog message was found, overwrite the orginial message and the syslog labels
#
if ($ELEMENTS{errpt_error_label} eq "SYSLOG" && $SYSLOG_MESSAGE ne "") {
  # some defaults for initialisation
  $ELEMENTS{severity} = 7;
  $ELEMENTS{facility} = 1;
  $ELEMENTS{message} = $SYSLOG_MESSAGE;
  # decode original SYSLOG message
  $SYSLOG_MESSAGE =~ m/^<(.+?)>(.+?) (.+?) (.+?) (.+?): (.*)/;
  $ELEMENTS{severity} = $1 & 7 if (defined $1);
  $ELEMENTS{severity_label} = $SEVERITY_LABEL[$ELEMENTS{severity}];
  $ELEMENTS{facility} = $1 >> 3 if (defined $1);
  $ELEMENTS{facility_label} = $FACILITY_LABEL[$ELEMENTS{facility}];
  $ELEMENTS{program} = $5 if (defined $5 && length($5));
  $ELEMENTS{message} = $6 if (defined $6 && length($6));
}
# cut of PID from program name
$ELEMENTS{program} =~ m/^(.+?)\[(.+?)\]/;
$ELEMENTS{program} = $1 if (defined $1 && length($1));
$ELEMENTS{program_pid} = $2 if (defined $2 && length($2));
#
# open tcp connection to the logstash server
#
my $SOCKET = IO::Socket::INET->new(Proto => "tcp", Timeout  => "2",
  PeerAddr => $SERVER_ADDR, PeerPort => $SERVER_PORT)
  or message_handler("ERROR","Unable to connect to [${SERVER_ADDR}:${SERVER_PORT}]: $!");
#
# build and send JSON string
#
my $JSON_STRING = "";
for $ELEMENT ( sort keys %ELEMENTS ) {
  $JSON_STRING .= "\"$ELEMENT\": \"$ELEMENTS{$ELEMENT}\"," ;
}
$JSON_STRING  = substr($JSON_STRING,0,(length($JSON_STRING)-1));
print $SOCKET "{".$JSON_STRING."}\n";
#
# if verbose mode is set print message to logfile
#
message_handler("INFO", "Send [$JSON_STRING] to [${SERVER_ADDR}:${SERVER_PORT}].") if ($VERBOSE);
#
# close connection and exit
#
$SOCKET->close();
close(LOGF);
exit(0);
