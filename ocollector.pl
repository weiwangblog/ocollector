#!/usr/bin/env perl
# author:        yanglei@snda.com
# last modified: 2011-04-12
# description:   this script collects interesting data then send to some place for scrunity.

use strict;
use warnings;
use File::Path;
use POSIX qw( strftime );
use Getopt::Long;
use IO::Socket;
use File::ReadBackwards;
use Sys::Statistics::Linux::DiskUsage;
use Date::Parse;
use File::Spec;
use Data::Dumper;
use Carp;
use Try::Tiny;
use Ocollector::ServiceMonitor::Memcached;
use Ocollector::AccountServer::StatisticDetails;
use Ocollector::AccountServer::Cache;
use Ocollector::AccountServer::DBComErr;
use Ocollector::AccountServer::AC;
use Ocollector::CloudStat::Wrapper;
use Ocollector::Nginx::SLA;
use Ocollector::Nginx::ErrorLog;
use Ocollector::Nginx::RegionLatency;
use Ocollector::IIS::Error2;
use Ocollector::Tcpbasic::Windows;
use Ocollector::NetAppliance::Cisco::Switch;

# Hacked oneline to remove dependency on version module, which requires a XS file that we can't pack.
our $VERSION = "1.15";
$VERSION = eval $VERSION;

my $O_ERROR = q{};

sub usage {
    my $type = shift;

    if ($type == 1) {
        die <<USAGE;
Usage: ocollector [options] -t type

Try `ocollector --help` or `ocollector -h` for more options.
USAGE
    }

    die <<HELP;
Usage: ocollector [options] -t type

Options:
    -v,--verbose                          Print the full collecting results
    -q,--quiet                            Suppress all output even error messages
    -h,--help                             Print this help
    -o,--to                               Specify the address where metrics send to, default: op.sdo.com
    -p,--port                             Specify the port where metrics got sent to, default: 4242
    -t,--type                             Specify the collecting type, default: tcpbasics

    --apparg                              application specific arguments, you can list them like: --apparg ostype=windows --apparg arch=x86_64

Types:
    Nginx::SLA                            Parse nginx log to calculate Website's SLA

Examples:

    curl -LO http://op.sdo.com/download/ocollector
    chomd +x ocollector

    ./ocollector -t Nginx::SLA --apparg interval=60 --apparg prefer=hostname --apparg cluster=Nanhui
    ./ocollector -t Nginx::SLA --apparg interval=60 --apparg prefer=hostname --apparg cluster=Nanhui --apparg virtual=yes

    ./ocollector -t Nginx::SLA --apparg interval=60 --apparg prefer=hostname --apparg cluster=Nanhui --verbose
    ./ocollector -t Nginx::SLA --apparg interval=60 --apparg prefer=hostname --apparg cluster=Nanhui --quiet

HELP

    return 1;
}

sub send_metrics {
    my ($results, $ocollector_daemon, $ocollector_port, $ocollector_proto) = @_;

    my $rc = 0;

    # send directly through IO::Socket
    my $sock = IO::Socket::INET->new(
        PeerAddr => $ocollector_daemon,
        PeerPort => $ocollector_port,
        Proto    => $ocollector_proto,
    );

    unless ($sock) {
        $O_ERROR = "create ${ocollector_daemon}:$ocollector_port failed";
        return 0;
    }

    print {$sock} $results;
    close $sock;

    return 1;
}

sub log_succeed {
    my $msg = shift;
    printf("%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S", localtime), "$msg");
}

sub log_exception {
    my $function = shift;
    printf("%s\t%s\n", strftime("%Y-%m-%d %H:%M:%S", localtime), "$function() failed: $O_ERROR\n");
}

sub main {
    # options

    my $ocollector_daemon       = 'op.sdo.com';
    my $ocollector_port         = 4242;
    my $ocollector_proto        = 'tcp';
    my $ocollector_version      = q{};
    my $ocollector_type         = q{};
    my $ocollector_verbose      = q{};
    my $ocollector_quiet        = q{};
    my $ocollector_apparg       = q{};
    my $help                    = q{};

    usage(1) if (@ARGV < 1);

    Getopt::Long::Configure("bundling");

    usage(2) unless GetOptions(
        "o|to=s" => \$ocollector_daemon,
        "p|port=i" => \$ocollector_port,
        "t|type=s" => \$ocollector_type,
        "q|quiet" => \$ocollector_quiet,
        "v|verbose" => \$ocollector_verbose,
        "V|version" => \$ocollector_version,
        "h|help" => \$help,
        "apparg=s%" => \$ocollector_apparg,
   );

    if ($ocollector_version) {
        print "ocollector version: $VERSION\n";
        exit 0;
    }

    usage(2) if $help;

    # plugin is a perl class
    my $supported = '(?:\w+::\w+)';

    if ($ocollector_type !~ /^(?:$supported)/ixsm) {
        croak "[$ocollector_type] is not a supported collecting type\n";
    }

    # build params hash for each collector type
    my $params;
    foreach my $arg (keys %{$ocollector_apparg}) {
        $params->{$arg} = $ocollector_apparg->{$arg};
    }

    # create module object and do the job
    my $module = "Ocollector::$ocollector_type";
    my $ot = $module->new($params);

    for (;;) {
        # Only send to tsd if we got a successful parse
        if (my $results = $ot->show_results) {
            if (send_metrics($results, $ocollector_daemon, $ocollector_port)) {
                if ($ocollector_verbose) {
                    log_succeed("send_metrics() succeed:\n$results") unless $ocollector_quiet;
                } else {
                    log_succeed("send_metrics() succeed.") unless $ocollector_quiet;
                }
            } else {
                log_exception('send_metrics') unless $ocollector_quiet;
            }
        } else {
            $O_ERROR = $ot->errormsg;
            log_exception('prepare_metrics') unless $ocollector_quiet;
            $ot->errormsg(q{});
        }

        sleep($ot->interval);
    }
}

main();
