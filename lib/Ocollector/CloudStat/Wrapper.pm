package Ocollector::CloudStat::Wrapper;

use strict;
use warnings;
use Net::Address::IP::Local;
use Sys::Hostname;

my @accessors = qw( tag_partial interval errormsg script );

use base qw(Class::Accessor Ocollector::Common);
Ocollector::CloudStat::Wrapper->mk_accessors(@accessors);


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
    my $rc = `$script`;
    if ($rc) {
        foreach (split /\n/, $rc) {
            chomp;
            $results .= sprintf("put %s %s\n", $_, $tag_partial);
        }
    }

    return $results;
}
