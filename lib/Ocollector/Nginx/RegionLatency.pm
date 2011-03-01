package Ocollector::Nginx::RegionLatency;

use strict;
use warnings;
use Net::Address::IP::Local;
use Sys::Hostname;

my @accessors = qw( tag_partial interval errormsg script );

use base qw(Class::Accessor Ocollector::Common);
Ocollector::Nginx::RegionLatency->mk_accessors(@accessors);


our $VERSION = '1.0';

sub new {
    my $class = shift;
    my $opts  = ref($_[0]) ? shift : {@_};

    my $self;
    foreach my $opt (keys %{$opts}) {
        $self->{$opt} = $opts->{$opt};
    }

    $self->{errormsg}  = '';

    my @tags;
    if ($self->{prefer} && $self->{prefer} =~ /hostname/ixsm) {
        push @tags, 'host=' . hostname;
    } else {
        push @tags, 'host=' . Net::Address::IP::Local->public_ipv4;
    }

    $self->{tag_partial} = join(' ', @tags);


    return bless $self, $class;
}

sub show_results {
    my $self = shift;

    my $results;
    my $tag_partial = $self->tag_partial;

    my $script = $self->script;
    my $s = time;
    my $rc = `$script`;
    my $cost = time - $s;
    if ($rc) {
        foreach (split /\n/, $rc) {
            chomp;
            my ($vendor, $region, $counts) = split /\t/;
            $results .= sprintf("put nginx.regioncount %d %d vendor=%s region=%s %s\n",
                time, $counts, $vendor, $region, $tag_partial);
        }
    }

    return $results;
}
