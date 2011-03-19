#!/usr/bin/env perl
# author:   yanglei@snda.com
# created:  2010-03-19
# vim conf: set et, ts=4, sw=4


use strict;
use warnings;
use Test::More;

BEGIN { use_ok( 'Ocollector::NetAppliance::Cisco::Switch' ); }
BEGIN { use_ok( 'Net::Address::IP::Local' ); }


my $tsd_data = {
   'fc2_5' => {
               'tx' => '16061142092',
               'errors' => 0,
               'discards' => 5190,
               'rx' => 1745382926
             },
  'fc2_19' => {
                'tx' => 0,
                'errors' => 0,
                'discards' => 0,
                'rx' => 0
              },
  'fc2_3' => {
               'tx' => 991996834,
               'errors' => 0,
               'discards' => 77730,
               'rx' => 480016798
             },
  'fc2_7' => {
               'tx' => '4370505415',
               'errors' => 0,
               'discards' => 0,
               'rx' => 2057392956
             },
  'fc2_4' => {
               'tx' => '8127280142',
               'errors' => 0,
               'discards' => 8283427,
               'rx' => 1725337440
             },
  'fc2_2' => {
               'tx' => 105780,
               'errors' => 282855,
               'discards' => 584835150,
               'rx' => 57980
             },
  'fc2_17' => {
                'tx' => 1534762020,
                'errors' => 0,
                'discards' => 0,
                'rx' => 1788218571
              },
  'fc2_8' => {
               'tx' => 31985,
               'errors' => 0,
               'discards' => 0,
               'rx' => 15402
             },
  'fc2_18' => {
                'tx' => '16189003908',
                'errors' => 2590,
                'discards' => 1256150,
                'rx' => 1737587724
              }
};



can_ok('Net::Address::IP::Local', qw/public_ipv4/);
can_ok('Ocollector::NetAppliance::Cisco::Switch', qw/build_log_targets show_results do_parse/);

sub log_build {
    my @should_logfiles;
    push @should_logfiles, File::Spec->catfile(q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs}, 'NH-MDS-1_summarylog.txt');
    push @should_logfiles, File::Spec->catfile(q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs}, 'NH-MDS-2_summarylog.txt');

    my $o1 = Ocollector::NetAppliance::Cisco::Switch->new(
        logdir  => q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs},
        logfile => q{NH-MDS-1_summarylog.txt,NH-MDS-2_summarylog.txt},
    );

    my $o2 = Ocollector::NetAppliance::Cisco::Switch->new(
        logdir  => q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs},
        logfile => q{NH-MDS-1_summarylog.txt, NH-MDS-2_summarylog.txt},
    );

    my $o3 = Ocollector::NetAppliance::Cisco::Switch->new(
        logdir  => q{C:\Program Files (x86)\Cisco Systems\dcm\fm\logs},
        logfile => q{NH-MDS-1_summarylog.txt , NH-MDS-2_summarylog.txt},
    );

    my @logfiles1 = $o1->build_log_targets;
    my @logfiles2 = $o2->build_log_targets;
    my @logfiles3 = $o3->build_log_targets;

    is_deeply(\@logfiles1, \@should_logfiles, 'log_build_1');
    is_deeply(\@logfiles2, \@should_logfiles, 'log_build_2');
    is_deeply(\@logfiles3, \@should_logfiles, 'log_build_3');
}

sub obtain_ip {
    my $o = Ocollector::NetAppliance::Cisco::Switch->new;
    like($o->tag_partial, qr/host=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ixsm, 'obtain_ip: ' . $o->tag_partial);
}

sub time_parse {
    my $o = Ocollector::NetAppliance::Cisco::Switch->new(
        logdir => '.',
        logfile => 'sample.log',
        debug => 1,
        interval => 10,
    );


    my $rc = $o->show_results;
    is_deeply($rc, $tsd_data, 'core logic verification');
}

log_build();
obtain_ip();
time_parse();

done_testing();
