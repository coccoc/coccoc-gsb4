package Gsb4::Lockf::Alarm;

use strict;
use warnings;

# ABSTRACT: alarm guard

=head1 DESCRIPTION

This module is necessary to implement timeouts in C<Coccoc::Lockf> class.

=head1 METHODS

=over

=item B<< new($timeout) >>

Construct new alarm guard object.

=cut
sub new ($$) {
    my ($class, $timeout) = @_;
    bless { 'alarm' => alarm($timeout), 'time' => time };
}

sub DESTROY ($) {
    my $self = shift;
    local $@;
    my $alarm;
    if ($self->{alarm}) {
        $alarm = $self->{alarm} + $self->{time} - time;
        $alarm = 1 if $alarm <= 0;
    } else {
        $alarm = 0;
    }
    alarm($alarm);
}

=back

=cut
1;
