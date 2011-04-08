package Ocollector::NetAppliance::Cisco::Switch;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use File::Spec;

my @accessors = qw( metric logdir logfile interval errormsg tag_partial debug tzdiff );

use base qw(Class::Accessor Ocollector::Common);
Ocollector::NetAppliance::Cisco::Switch->mk_accessors(@accessors);

our $VERSION = '1.0';

my $date_fmt_re = qr/\d{4}\/\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}/ixsm;

sub new {
    my $class = shift;

    my $opts  = ref($_[0]) ? shift : {@_};

    # 允许用户指定
    my $self;
    $self->{logdir}    = q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs};
    $self->{logfile}   = 'NH-MDS-1_summarylog.txt,NH-MDS-2_summarylog.txt';
    $self->{metric}    = 'NetAppliance.Cisco.Switch';
    $self->{tzdiff}    = 0;
    $self->{interval}  = 10;
    $self->{errormsg}  = '';
    $self->{debug}     = '';

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

    my @logfiles = map { File::Spec->catfile($self->logdir, $_) } split /\s*,\s*/, $self->logfile;
    return @logfiles;
}

sub do_parse {
    my $self = shift;

    my $timefrm = $self->interval;
    my ($logfile) = @_;


    my $stop = time() - $timefrm;

    # if the timezone is provided, adjust stop value from the current timezone 
    # for example, if we are in +8 and the log is written in -12, timezone should be set to 20
    if ($self->tzdiff != 0) {
        $stop -= $self->tzdiff * 3600;
    }

    my $rc;
    my $bw = File::ReadBackwards->new($logfile);
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            if ($line =~ /($date_fmt_re)/ixsm) {
                # convert 2011/03/17-22:49:49 to 2011-03-17 22:49:49
                my $ts = $1;
                $ts =~ s/-/ /;
                $ts =~ s/\//-/g;

                my $msec = str2time($ts);
                if ($msec < $stop && !$self->debug) {
                    last BACKWARD_READ;
                } else {
                    my ($interface, $rx, $tx, $error, $discard) = split /\s+/, $line;
                    if ($interface eq 'Interface') {
                        next BACKWARD_READ; # see a header line
                    } else {
                        $interface =~ s/\//_/;
                        $rc->{$interface}->{rx} += $rx;
                        $rc->{$interface}->{tx} += $tx;
                        $rc->{$interface}->{errors} += $error;
                        $rc->{$interface}->{discards} += $discard;
                    }
                }
            }
        }
    }

    return $rc;
}

sub show_results {
    my $self = shift;

    my @logfiles = $self->build_log_targets();

    my $results;

    foreach my $logfile (sort @logfiles) {
        my $rc = $self->do_parse($logfile);
        foreach my $interface (sort keys %{$rc}) {
            my $rx        = $rc->{$interface}->{rx};
            my $tx        = $rc->{$interface}->{tx};
            my $errors    = $rc->{$interface}->{errors};
            my $discards  = $rc->{$interface}->{discards};

            $results .= sprintf("put %s.rx %d %.0f interface=%s %s\n",
                $self->metric, time(), $rx, $interface, $self->tag_partial);

            $results .= sprintf("put %s.tx %d %.0f interface=%s %s\n",
                $self->metric, time(), $tx, $interface, $self->tag_partial);

            $results .= sprintf("put %s.error %d %.0f interface=%s %s\n",
                $self->metric, time(), $errors, $interface, $self->tag_partial);

            $results .= sprintf("put %s.discard %d %.0f interface=%s %s\n",
                $self->metric, time(), $discards, $interface, $self->tag_partial);
        }

        if ($self->debug) {
            return $rc;
        }
    }

    return $results;
}


1;
