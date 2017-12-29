#!/usr/bin/perl
#===============================================================================
# Script        : errpt2logstash.pl
#
# Description   : Forward (and transform) ERRPT events to a logstash server.
#
# Author        : Ron Wellnitz
#
# Version       : 0.4
#-------------------------------------------------------------------------------
#
# History:
#
# <DATE>        <AUTHOR>        <REASON>
# ----------    --------------  ------------------------------------------------
# 2015-01-26    Ron Wellnitz    Initial creation
# 2015-01-28    Ron Wellnitz    Bugfixing, improved argument parsing
# 2015-02-03    Ron Wellnitz    Add errpt description field
#                               Fixing error_id to hexadecimal integer
# 2015-03-23    Ron Wellnitz    Adjusted comments, small improvements
# 2017-12-29    Ron Wellnitz    Add support for script output to a logfile
#                               Extend configuration file check
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
my $MAXLOGCOUNT = 4000;

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

# initial user configuration variables (Defaults)
my $SERVER_ADDR           = "localhost";
my $SERVER_PORT           = "5555";
my $IGNORE_SYSLOG         = 0;
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

# process script arguments $1 - $9
foreach ("errpt_sequence_number", "errpt_error_id",       "errpt_class",
         "errpt_type",            "errpt_alert_flags",    "errpt_resource_name",
         "errpt_resource_type",   "errpt_resource_class", "errpt_error_label") {

  $ELEMENTS{$_} = ($#ARGV + 1) ? shift : 'unset';
  if(( "$_" eq "errpt_error_id") && ($ELEMENTS{$_} =~ /^0x[0-9a-f]+/)) {
    (my $dummy, $ELEMENTS{$_}) = split(/0X/,uc($ELEMENTS{$_}));
  }
}

# touch logfile if necessary
# if logfile is not accessable go ahead without logging
if( ! -f $LOGFILE) {
  if(open(LOGF,'>',"$LOGFILE")) {
    close(LOGF);
  } else {
    $LOG_ENABLED = 0;
    message_handler("WARNING","Unable to open Logfile [$LOGFILE]: $!");
  }
}

# logfile handling incl. cleanup
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


# parse configuration file
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
   if ($_ =~ /enable_logging/) {
      (my $dummy,$LOG_ENABLED) = split(/=/,$_);
   }
}
close(FILE);

# check for misconfigurations (e.g. empty config file)
if(!$SERVER_ADDR || !$SERVER_PORT || $SERVER_PORT !~ /^[0-9]+$/) {
  message_handler("ERROR", "Invalid Server [$SERVER_ADDR] and/or Port [$SERVER_PORT] in configuration file [$CONFIGFILE]!");
}

if($IGNORE_SYSLOG !~ /^[0-1]$/) {
  message_handler("ERROR", "Invalid value [$IGNORE_SYSLOG] for <ignore_syslog_messages> in configuration file [$CONFIGFILE]!");
}

if($LOG_ENABLED !~ /^[0-1]$/) {
  message_handler("ERROR", "Invalid value [$LOG_ENABLED] for <enable_logging> in configuration file [$CONFIGFILE]!");
}

# if set "ignore syslog messages" to true this script ends
if ($IGNORE_SYSLOG && $ELEMENTS{errpt_error_label} eq "SYSLOG") {
  close(LOGF) if $LOG_ENABLED;
  exit(0);
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
my $SOCKET = IO::Socket::INET->new(Proto => "tcp", Timeout  => "2",
  PeerAddr => $SERVER_ADDR, PeerPort => $SERVER_PORT)
  or message_handler("ERROR","Unable to connect to [${SERVER_ADDR}:${SERVER_PORT}]: $!");

# build and send JSON string
my $JSON_STRING = "{";
for $ELEMENT ( sort keys %ELEMENTS ) {
  $JSON_STRING .= "\"$ELEMENT\": \"$ELEMENTS{$ELEMENT}\"," ;
}
$JSON_STRING  = substr($JSON_STRING,0,(length($JSON_STRING)-1));

# if logging mode is set, also print the message to the logfile (for debugging)
message_handler("INFO", "Send [$JSON_STRING] to [${SERVER_ADDR}:${SERVER_PORT}].") if ($LOG_ENABLED);

$JSON_STRING .= "}\n";
print $SOCKET $JSON_STRING;

# close connection and exit
$SOCKET->close();
close(LOGF) if $LOG_ENABLED;
exit(0);
