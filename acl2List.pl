#!/usr/bin/env perl
# author:        yanglei@snda.com
# last modified: 2011-03-01
# description:   this script parse CDN's ip to region table and import the results into memcached.

use strict;
use warnings;
use Data::Dumper;
use Cache::Memcached::Fast;

sub parse_acl_list {
    my ($vendor, $region);
    my $rc;
    my $re_ipv4_with_prefix = qr/(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))\/(?:\d{1,2})/ixsm;;
    while (<>) {
        if (/acl \s+ "(\w+)_(\w+)"/ixsm) {
            ($vendor, $region) = ($1, $2) 
        }
        else {
            while (/($re_ipv4_with_prefix);?/g) {
                $rc->{$1} = [$vendor, $region];
            }
        }
    }

    return $rc;
}

sub conn_memcached {
    my $memd = Cache::Memcached::Fast->new({
         servers => [ { address => '10.65.11.30:11211', noreply => 1 } ],
         # connect_timeout => 0.2,
         # io_timeout => 0.5,
         # max_failures => 3,
         # failure_timeout => 2,
         nowait => 1,
         # utf8 => ($^V ge v5.8.1 ? 1 : 0),
         # max_size => 512 * 1024,
    });

    unless (defined $memd) {
        die "failed to connect to memcached\n";
    }

    return $memd;
}

sub load_into_memcached {
    my ($memd, $rc) = @_;

    my ($rand_kv_verification);
    my $expiration_time = 86400*30; # 1 month
    foreach my $prefix (keys %{$rc}) {
        my ($region, $vendor) = @{$rc->{$prefix}};
        my ($k, $v) = ($prefix, "$region,$vendor");
        $memd->set($k, $v, $expiration_time);
        $rand_kv_verification->{$k} = $v if int(rand(100)) == 35;
    }

    return $rand_kv_verification;
}

sub main {
    my $memd = conn_memcached();
    print "connected to memcached.\n";

    my $rc;
    {
        print "start parsing acl list...\n";
        my $s = time;
        $rc = parse_acl_list();
        my $cost = time - $s;
        print "parse acl list done, spend $cost secs.\n";
    }
    
    my $rand_kv_verification;
    {
        print "start import memcached...\n";
        my $s = time;
        $rand_kv_verification = load_into_memcached($memd, $rc);
        my $cost = time - $s;
        print "import memcached done, spend $cost secs.\n";
    }

    {
        print "start verify memcached import...\n";
        my $s = time;
        my ($succeed, $total);
        foreach my $k (keys %{$rand_kv_verification}) {
            $total++;
            my $v = $memd->get($k);
            $succeed++ if $v =~ /\w+,\w+/;
        }
        my $cost = time - $s;
        printf("Verification over, cost %d sec. Result: succeed/total => %d\/%d\n", $cost, $succeed, $total);
    }
}

main();
