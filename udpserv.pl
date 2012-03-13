#!/usr/bin/perl -w
$|++;
use strict;
use IO::Socket;

my $server = IO::Socket::INET->new(LocalPort=>4242,Proto=>"udp") or die "Can't create UDP server: $@";
my ($datagram,$flags);
#
while ($server->recv($datagram,42,$flags)) {
  my $ipaddr = $server->peerhost;
  print "UDP from $ipaddr, flags ",$flags || "none",": $datagram\n";
  #my $response = IO::Socket::INET->new(Proto=>"udp",PeerHost=>$ipaddr,
        +PeerPort=>2424);
}
