package Ocollector::Nginx::SLA;

use strict;
use warnings;
use Date::Parse;
use Data::Dumper;
use File::Spec;
use Carp;
use Sys::Hostname;
use Sys::Statistics::Linux::DiskUsage;

my @accessors = qw(metric logfile interval errormsg prefer cluster threshold myself virtual);

use base qw(Class::Accessor Ocollector::Common);
Ocollector::Nginx::SLA->mk_accessors(@accessors);

our $VERSION = '1.0';

my $re_ipv4 = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))/ixsm;
my $re_ipv4_nginx_xff = qr/(?:$re_ipv4)(?: \,? \s+ $re_ipv4)*/ixsm;
my $re_static = qr/\.(?:gif|png|jpg|jpeg|js|css|swf)/ixsm;
my $re_domain = qr/(?:[0-9A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?(?:\.[A-Za-z](?:(?:[-A-Za-z0-9]){0,61}[A-Za-z0-9])?)*)/ixsm;
my $re_uri = qr/[^ ]+/ixsm;
my $re_qstring = qr/(?:[^ ]+|-)/ixsm;
my $re_msec = qr/\d{10}\.\d{3}/ixsm;
my $re_status = qr/\d{3}|-/ixsm;
my $re_cost = qr/(?:\d+\.\d+|-|\d+)/ixsm;
my $re_static_err = qr/(?:5\d{2}|404)/ixsm;
my $re_dynamic_err = qr/(?:5\d{2})/ixsm;


sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    # Allow user to customize, but provide sensible defaults
    my $self;
    $self->{logfile}    = '/dev/shm/nginx_metrics/metrics.log';
    $self->{interval}   = 60;
    $self->{prefer}     = 'ip';
    $self->{cluster}    = 'none';
    $self->{threshold}  = 90;
    $self->{errormsg}   = '';
    $self->{virtual}    = 'no';
    $self->{myself}     = Net::Address::IP::Local->public_ipv4;
    

    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    # Test logfile existance
    unless (-e $self->{logfile}) {
        # Of course, we can't work without a logfile, but we'd like to give user as much freedom as possible,
        # so we just warn them and pervail.
        carp $self->{logfile} . ' does not exist.';
    }

    my @tags;
    if ($self->{prefer} =~ /hostname/ixsm) {
        push @tags, 'host=' . hostname;
    } else {
        push @tags, 'host=' . $self->{myself};
    }

    $self->{tag_partial} = join(' ', @tags);

    return bless $self, $class;
}

sub do_parse {
    my $self = shift;

    my $timefrm = $self->interval;
    my $logfile = $self->logfile;

    my $stop = time() - $timefrm;

    my ($rc_dynamic, $rc_static);

    my $bw = File::ReadBackwards->new($logfile);
    if ($bw) {
        BACKWARD_READ:
        while (defined (my $line = $bw->readline)) {
            chomp $line;

            if ($line =~ /^($re_msec) \s+ ($re_domain|$re_ipv4) \s+ ($re_uri) \s+ ($re_status) \s+ ($re_ipv4:\d+|-) \s+ $re_ipv4_nginx_xff \s+ ($re_cost|-)$/ixsm) {
                my ($msec, $domain, $uri, $status, $upstream, $cost) = ($1, $2, $3, $4, $5, $6);

                if ($msec < $stop) {
                    last BACKWARD_READ;
                } else {
                    # remove port   
                    $upstream =~ s/:\d+//g;

                    if ($domain =~ $re_ipv4) {
                        # It's weird that the domain part is an IP address, so we don't process them now
                        next BACKWARD_READ;
                    } else {
                        if ($uri eq '-') {
                            # sometimes uri can be empty, 
                            # 1302221251.460 aig.sdo.com - 400 - 10.129.1.230 -
                            next BACKWARD_READ;
                        }

                        if ($uri !~ $re_static) {
                            if ($upstream eq '-') {
                                # If upstream_addr is empty, Nginx must process the dynamic request itself. for example:
                                # 1302239999.636 www.sdo.com /center/index.asp 301 - 180.119.181.98, 127.0.1.1, 10.129.1.230 -
                                # 1302239916.110 www.sdo.com /center/index.asp 301 - 58.17.160.47, 127.0.1.1, 10.129.1.230 -

                                # No matter who process the request, it's a dynamic one indeed, thus we must process them
                                # The biggest problem is that if nginx process the request itself, upstream_response_time is zero.
                                # we can't help but write a 3ms cost, this won't give too much confidence to nginx.
                                $cost = 0.003;

                                # upstream address is nginx itslef now, so we use hostname/ip address, depend on user choice
                                $upstream = $self->myself;
                            }

                            if ($cost eq '-') {
                                # It's impossible for a dynamic request with non-empty upstream_addr has empty cost, skip them
                                next BACKWARD_READ;
                            }

                            if ($status =~ /($re_dynamic_err)/) {
                                $rc_dynamic->{$domain}->{$upstream}->{error}->{$1}++;
                            }

                            $rc_dynamic->{$domain}->{$upstream}->{latency} += $cost;
                            $rc_dynamic->{$domain}->{$upstream}->{throughput}++;
                        }
                        else {
                            # Nginx cached the response, so the upstream is -
                            if ($upstream eq '-') {
                                # For static content, the latency value is not that useful. We give a 1ms here
                                $cost = 0.001;

                                $upstream = $self->myself;
                            }

                            if ($cost eq '-') {
                                # It's impossible for a dynamic request with non-empty upstream_addr has empty cost, skip them
                                next BACKWARD_READ;
                            }

                            # Currently, 404 is an error
                            if ($status =~ /($re_static_err)/) {
                                $rc_static->{$domain}->{$upstream}->{error}->{$1}++;
                            }

                            $rc_static->{$domain}->{$upstream}->{latency} += $cost;
                            $rc_static->{$domain}->{$upstream}->{throughput}++;
                        }
                    }
                }
            }
        }
    } else {
        $self->errormsg("open $logfile failed");
        return undef;
    }

    return ($rc_dynamic, $rc_static);
}

sub show_results {
    my $self = shift;

    # If logfile in tmpfs, we won't do any harm.
    # If logfile is not in tmpfs, tmpfs can't reach threshold.(flush_tmpfs always return 0)
    if ($self->flush_tmpfs) {
        system '>' . $self->logfile;

        # so the logfile has beed flushed, we just report to outer function
        $self->errormsg('tmpfs flushed');
        return 0;
    }

    my $results;
    my ($rc_dynamic, $rc_static) = $self->do_parse;

    if (defined $rc_dynamic) {
        foreach my $domain (keys %{$rc_dynamic}) {
            foreach my $upstream (keys %{$rc_dynamic->{$domain}}) {
                my $errors = 0;

                # If no error found, set number of errors to zero
                unless (exists $rc_dynamic->{$domain}->{$upstream}->{error}) {
                    $errors = 0;
                }

                foreach my $item (keys %{$rc_dynamic->{$domain}->{$upstream}}) {
                    # process latency here
                    if ($item eq 'latency') {
                        $results .= sprintf("put nginx.latency %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s type=dynamic\n",
                            time(),
                            ($rc_dynamic->{$domain}->{$upstream}->{latency}/$rc_dynamic->{$domain}->{$upstream}->{throughput})*1000,
                            $self->myself,
                            $domain,
                            $upstream,
                            $self->virtual,
                            $self->cluster,
                        );
                    } elsif ($item eq 'throughput') {
                        $results .= sprintf("put nginx.throughput %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s type=dynamic\n",
                            time(),
                            $rc_dynamic->{$domain}->{$upstream}->{throughput},
                            $self->myself,
                            $domain,
                            $upstream,
                            $self->virtual,
                            $self->cluster,
                        );
                    } elsif ($item eq 'error') {
                        foreach my $err (keys %{$rc_dynamic->{$domain}->{$upstream}->{error}}) {
                            $results .= sprintf("put nginx.error %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s code=%s type=dynamic\n",
                                time(),
                                $rc_dynamic->{$domain}->{$upstream}->{error}->{$err},
                                $self->myself,
                                $domain,
                                $upstream,
                                $self->virtual,
                                $self->cluster,
                                $err,
                            );
                        }
                    } else {
                        # impossible
                        1;
                    }
                }
            }
        }
    }
        
    if (defined $rc_static) {
        foreach my $domain (keys %{$rc_static}) {
            foreach my $upstream (keys %{$rc_static->{$domain}}) {
                my $errors = 0;

                # If no error found, set number of errors to zero
                unless (exists $rc_static->{$domain}->{$upstream}->{error}) {
                    $errors = 0;
                }

                foreach my $item (keys %{$rc_static->{$domain}->{$upstream}}) {
                    # process latency here
                    if ($item eq 'latency') {
                        $results .= sprintf("put nginx.latency %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s type=static\n",
                            time(),
                            ($rc_static->{$domain}->{$upstream}->{latency}/$rc_static->{$domain}->{$upstream}->{throughput})*1000,
                            $self->myself,
                            $domain,
                            $upstream,
                            $self->virtual,
                            $self->cluster,
                        );
                    } elsif ($item eq 'throughput') {
                        $results .= sprintf("put nginx.throughput %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s type=static\n",
                            time(),
                            $rc_static->{$domain}->{$upstream}->{throughput},
                            $self->myself,
                            $domain,
                            $upstream,
                            $self->virtual,
                            $self->cluster,
                        );
                    } elsif ($item eq 'error') {
                        foreach my $err (keys %{$rc_static->{$domain}->{$upstream}->{error}}) {
                            $results .= sprintf("put nginx.error %d %d host=%s domain=%s upstream=%s virtualized=%s cluster=%s code=%s type=static\n",
                                time(),
                                $rc_static->{$domain}->{$upstream}->{error}->{$err},
                                $self->myself,
                                $domain,
                                $upstream,
                                $self->virtual,
                                $self->cluster,
                                $err,
                            );
                        }
                    } else {
                        # impossible
                        1;
                    }
                }
            }
        }
    }

    if ($results eq '') {
        $self->errormsg('empty parse');
    }

    return $results;
}


sub flush_tmpfs {
    my $self = shift;
    my $lxs = Sys::Statistics::Linux::DiskUsage->new;
    my $stat = $lxs->get;
    my $threshold = $self->threshold;

    if (exists $stat->{tmpfs}) {
        my ($free, $total) = ($stat->{tmpfs}->{free}, $stat->{tmpfs}->{total});

        # 大小为0的tmpfs可能存在么？
        if ($total >= 0) {
            my $used = sprintf("%.2f", ($total - $free)/$total*100);
            # 低于这点时开始flush 
            if ($used >= $threshold) {
                return 1;
            }
        }
    }

    return 0;
}

1;
