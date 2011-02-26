package Ocollector::IIS::Error2;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;

my @accessors = qw(metric logdir logfile interval errormsg tag_partial);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::IIS::Error2->mk_accessors(@accessors);

our $VERSION = '1.0';

# Fields: date time c-ip c-port s-ip s-port cs-version cs-method cs-uri sc-status s-siteid s-reason s-queuename
# 2011-02-25 11:18:33 119.188.13.68 4010 61.172.251.22 4387 HTTP/1.1 GET /Protect/SessionSvrDispatch.asp?type=89&area=9&server=4 503 447434323 AppOffline DefaultAppPool
# 2011-02-25 11:18:33 222.73.21.124 48833 61.172.251.22 4387 HTTP/1.1 GET /Protect/SessionSvrDispatch.asp?type=41&area=1&server=1 503 447434323 AppOffline DefaultAppPool
# 2011-02-25 11:18:33 210.51.29.203 1977 61.172.251.22 4387 HTTP/1.1 GET /Protect/SessionSvrDispatch.asp?type=41&area=1&server=1 503 447434323 AppOffline DefaultAppPool
# 2011-02-25 12:46:36 115.238.116.5 3741 61.172.251.22 4387 - - - - - Timer_ConnectionIdle -

#======================================================================
# The documetation of HTTP Error can be found at:
# http://support.microsoft.com/default.aspx?scid=kb;en-us;820729

my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
my $re_ipv4_iis_xff = qr/($re_ipv4)(?:\,?\+$re_ipv4\,?)*/ixsm;
my $re_uri = qr/(?:[^ ]+|-)/ixsm;
my $re_status = qr/\d+|-/ixsm;
my $re_port = qr/\d+/ixsm;
my $re_httpver = qr/(?:HTTP\/[\d.]+|-)/ixsm;
my $re_method = qr/(?:\w+|-)/ixsm;
my $re_siteid = qr/(?:\d+|-)/ixsm;
my $re_reason = qr/(?:AppOffline|AppPoolTimer|AppShutdown|Connection_Abandoned_By_AppPool|Connection_Abandoned_By_ReqQueue|Connection_Dropped|Connection_Dropped_List_Full|ConnLimit|Connections_Refuse|Disabled|EntityTooLarge|Internal|Header|Forbidden|FieldLength|Hostname|N\/A|N\/I|QueueFull|Timer_AppPool|RequestLength|Timer_ReqQueue|-)/ixsm;
my $re_queuename = qr/(?:[\w.]+|-)/ixsm;
my $re_httperr = qr/httperr\d+\.log/ixsm;
my $re_iis_time = qr/\d{4}-\d{2}-\d{2} \s \d{2}:\d{2}:\d{2}/ixsm;
my $re_iis6_httperr = qr/$re_iis_time \s $re_ipv4_iis_xff \s $re_port \s ($re_ipv4) \s $re_port \s $re_httpver \s $re_method \s $re_uri \s ($re_status) \s $re_siteid \s ($re_reason) \s ($re_queuename)/ixsm;

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    # 允许用户指定
    my $self;
    $self->{logdir}    = "C:\\WINDOWS\\system32\\LogFiles\\HTTPERR";
    $self->{metric}     = 'iis.error2';
    $self->{errormsg}   = '';

    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    my @tags;
    push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;

    $self->{tag_partial} = join(' ', @tags);

    return bless $self, $class;
}

sub do_parse {
    my $self = shift;

    my $timefrm = $self->interval;
    my $logfile = $self->determin_iislog;

#   print "logfile is: $logfile\n";

    my $stop = time() - $timefrm;

    my $bw = File::ReadBackwards->new($logfile);
    my $rc;
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            # debug purpose
#           if ($self->logfile) {
#               if ($line =~ $re_iis6_httperr) {
#                   my ($cip, $sip, $status, $reason, $queuename) = ($1, $2, $3, $4, $5);
#                   print "$sip, $status, $reason, $queuename\n";

#                   if ($reason eq '-') { $reason = 'none' };
#                   if ($queuename eq '-') { $queuename = 'none' };

#                   # 不计算非500的错误 
#                   if ($status =~ /^5\d{2}/ixsm) {
#                       $rc->{$sip}->{$queuename}->{$reason}++;
#                   } else {
#                       next BACKWARD_READ;
#                   }
#               } else {
#                   next BACKWARD_READ;
#               }

#               last BACKWARD_READ;
#           }

            if ($line =~ qr/($re_iis_time)/ixsm) {
                my $msec = str2time($1);

                if ($msec < $stop) {
                    last BACKWARD_READ;
                } else {
                    if ($line =~ $re_iis6_httperr) {
                        my ($cip, $sip, $status, $reason, $queuename) = ($1, $2, $3, $4, $5);

                        if ($reason eq '-') { $reason = 'none' };
                        if ($queuename eq '-') { $queuename = 'none' };

                        # 不计算非500的错误 
                        if ($status =~ /^5\d{2}/ixsm) {
                            $rc->{$sip}->{$queuename}->{$reason}++;
                        } else {
                            next BACKWARD_READ;
                        }
                    } else {
                        next BACKWARD_READ;
                    }
                }
            }
        }
    } else {
        $self->errormsg("failed to open $logfile");
        return undef;
    }

    unless (defined $rc) {
        $self->errormsg("empty parse");
    }

    return $rc;
}


sub show_results {
    my $self = shift;

    my $rc = $self->do_parse;
    my $results;

    my $metric = $self->metric;
    my $tag_partial = $self->tag_partial;
    foreach my $queuename (sort keys %{$rc}) {
        foreach my $reason (sort keys %{$rc->{$queuename}}) {
            $results .= sprintf("put %s %d %d queuename=%s reason=%s %s\n",
                    $metric, time, $rc->{$queuename}->{$reason}, $queuename, $reason, $tag_partial);
        }
    }

    return $results;
}

sub determin_iislog {
    my $self = shift;

    my $logdir = $self->logdir;

    # 如果指定了logfile，就不自动选取
    # 可用于Debug 
    if ($self->logfile) {
        return $logdir . '\\' . $self->logfile;
    }

    my $dir_fh;
    opendir $dir_fh, $logdir;

    unless ($dir_fh) {
        $self->errormsg("failed to open dir: $logdir");
        return undef;
    }

    my $rc;
    while ((my $filename = readdir($dir_fh))) {
        # 跳过不符合IIS日志(httperr\d+.log)
        next unless $filename =~ $re_httperr;

        # 然后取mtime最大的
        my $full_filename = File::Spec->catfile($logdir, $filename);
        my $mtime = (stat($full_filename))[9];
        $rc->{$mtime} = $full_filename;
    }

    my @sorted = sort { $b <=> $a } keys %{$rc};
    my $this_file = $rc->{$sorted[0]};

    unless ($this_file) {
        $self->errormsg("failed to obtain iis logfile, no max mtime");
    }

    return $this_file;
}

1;
