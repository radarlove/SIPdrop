#!/usr/bin/perl
use IO::Socket::INET;

$| = 1;

my ($socket, $data);

$socket = new IO::Socket::INET ( PeerAddr => '192.168.2.143:8081', Proto   => 'udp') or die "cant";

while (1) {
    $data = <>;
    $socket->send($data);
    if ($data =~ /quit/) {
        last;
    }
}

sleep(1);
$socket->close();

