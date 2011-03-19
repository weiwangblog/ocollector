package Ocollector::NetAppliance::Cisco::Switch;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use File::Spec;

my @accessors = qw( metric logdir logfile interval errormsg);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::NetAppliance::Cisco::Switch->mk_accessors(@accessors);

our $VERSION = '1.0';

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    # 允许用户指定
    my $self;
    $self->{logdir}    = q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs};
    $self->{metric}    = 'NetAppliance.Cisco.Switch';
    $self->{errormsg}  = '';
    $self->{logfile}   = 'NH-MDS-1_summarylog.txt,NH-MDS-2_summarylog.txt';

    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    $self->{tag_partial} = join(' ', @tags);

    return bless $self, $class;
}

sub build_log_targets {
    my $self = shift;
    my ($logdir, $logfile) = @_;

    my @logfiles = map { File::Spec->catfile($logdir, $_) } split /,\s*/, $logfile;

    return @logfiles;
}


1;
