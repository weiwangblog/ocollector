package Ocollector::AccountServer::DBComErr;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use Net::Address::IP::Local;

my @accessors = qw( metric logdir logname tag_partial interval errormsg pattern );

use base qw(Class::Accessor Ocollector::Common);
Ocollector::AccountServer::DBComErr->mk_accessors(@accessors);

our $VERSION = '1.0';

# 我们假设DBComErr不会很大，所以每次读取当天的总行数
# DBComErr.log文件仅在出异常时生成，所以先判断文件是否存在

my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self;
    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    $self->{metric}    = 'AccsvrStats.DBComErr';
    $self->{errormsg}  = '';

    # 14:45:34.324  [ip=10.126.7.112]strError=[DBNETLIB][ConnectionWrite (send()).]
    $self->{pattern}   = qr/^\d{2}:\d{2}:\d{2}\.\d{3} \s+ \[ip=($re_ipv4)\]strError=\[DBNETLIB\]\[ConnectionWrite\s\(send\(\)\)\.\]/ixsm;

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    if (exists $self->{svcgrp}) {
        push @tags, 'svcgrp=' . $self->{svcgrp};
    } else {
        push @tags, 'svcgrp=rachel';
    }

    $self->{tag_partial} = join(' ', @tags);
    

    return bless $self, $class;
}

sub show_results {
    my ($self) = @_;

    my $logfile = $self->determine_log($self->logdir, $self->logname);
    my $pattern = $self->pattern;

    my $results;
    my $rc;

    if (-e $logfile) {
        open my $fh, '<', $logfile;
        if ($fh) {
            while (defined (my $line = <$fh>)) {
                if ($line =~ $pattern) {
                    $rc->{$1}++;
                }
            }

            foreach my $db (sort keys %{$rc}) {
                $results .= sprintf("put %s %d %d database=%s %s\n", $self->metric, time, $rc->{$db}, $db, $self->{tag_partial});
            }
        } else {
            $self->errormsg("open logfile: $logfile failed");
        }
    } else {
        $self->errormsg("logfile: $logfile does not exists");
    }

    return $results;
}
