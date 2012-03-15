#!/usr/bin/perl

'
 Copyright (c) 2012, Richard Liming
 All rights reserved.

 * RTP packet disassembly code is (c) Steffen Ullrich, copied from the Perl
   Net::SIP::Simple::RTP module.

 Redistribution and use in source and binary forms, with or without 
 modification, are permitted provided that the following conditions 
 are met:

 * Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
   notice, this list of conditions and the following disclaimer in 
   the documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 THE POSSIBILITY OF SUCH DAMAGE.

 There are legal ramifications to recording phone conversations.  
 It is your responsibilty to understand any applicable laws before
 using this software.  Typically, you must notify the parties that
 they are about to be recorded and/or provide audible tones to
 indicate recording is in progress.


';

# sipdrop.pl -  Record SIP/RTP phone calls.
#               Parse SIP for SDP records and RTP info. Capture RTP/mulaw packets. 
#               Controlled through UDP messages.
#
#               saved file name is the SIP cid of remote end followed by the 
#               IP address: de2bc7b402cbf8cd\@192.168.1.179
#
#       play -  aplay -r 8000 -c 1 -f MU_LAW -t raw de2bc7b402cbf8cd\@192.168.1.179
#    convert -  ffmpeg -ar 8000 -ac 1 -f mulaw -i de2bc7b402cbf8cd\@192.168.1.179 test.wav
#               sox/bin/sox -t ul -c 1 -r 8000 de2bc7b402cbf8cd\@192.30.168.179.raw test.wav


#use strict;
#use Data::Dumper;
use Net::PcapUtils;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::UDP;

my $start = time();
my $record_timeout = 30;
my $control_server = '192.168.2.138';
my $control_recv_port = 8081;
my $control_send_port = 4242;

my $cnt=0;
my %ctab;
my %active;
my %bykey;
my %byip;
my %record;

open(LOG,">new.log") or die "Can't log\n";

# For responses back to the control_server

use IO::Socket::INET;
my $socket = IO::Socket::INET->new( PeerAddr => "$control_server:$control_send_port", 
                                    Proto => 'udp') or die "Can't connect\n";

sub process_pkt {
	my($arg, $hdr, $pkt) = @_;
	my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
	my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
	my $dport = $udp_obj->{dest_port};
	my $sport = $udp_obj->{src_port};
    my $srcip = $ip_obj->{src_ip};
    my $destip = $ip_obj->{dest_ip};
    my $cid;
    my $key;
    my $rh;
    my ($remote, $local, $rkey, $lkey);

    $cnt++;
    if ($udp_obj->{dest_port} == $control_recv_port) {  # recv'd command
        if ($udp_obj->{data} =~ /quit/) {   # stop recording(s), n shut er down
            foreach $key (keys %active) {
                close ($active{$key});
            }
            print "Gotta go!\n";
            exit;
            $socket->close();
        }
        if ($udp_obj->{data} =~ /show/) {
            my $msg;
            foreach $key (keys %active) {
                $rcnt++;
                $msg .= "callid: $key\n";
            }
            $socket->send("cnt: $rcnt, $msg");
        }
        if ($udp_obj->{data} =~ /record (.+)/) {
            $client = $1;
            $client =~ s/\s+//g;
            $record{$client} = 1;
        }
        if ($udp_obj->{data} =~ /stop (.+)/) {
            $client = $1;
            $client =~ s/\s+//g;
            delete $record{$client};
        }
    }
    if ($ip_obj->{src_ip} eq "$control_server") {
        print "$ip_obj->{src_ip}, $ip_obj->{dest_ip}, $udp_obj->{src_port}, $udp_obj->{dest_port}\n";
    }
	if ($udp_obj->{src_port} == 5060 or $udp_obj->{dest_port} == 5060) {
        logp('Sinfo', $cnt, $ip_obj, $udp_obj);
        my $sip = parse_sip($udp_obj->{data});	
        $cid = $sip->{cid};
        print "meth:$sip->{meth}:\n";
		if ($sip->{meth} eq 'BYE') {
            $rkey = $ip_obj->{dest_ip} . ':' . $udp_obj->{dest_port};
            #print "bye key: $rkey\n";
            if ($active{$rkey}) {
                print "closing recording $rkey\n";
                close ($active{$rkey});
            }
		}
        if ($sip->{meth} eq 'INVITE' and $sip->{c}->{addr}) {
            $cid = $sip->{cid};
            $ctab{$cid}{remote} = $sip;
        }
        if ($sip->{code} == 200 and $sip->{type} eq 'response' and $sip->{cseqtxt} eq 'INVITE') {
            $ctab{$cid}{local} = $sip;
            $local = $ctab{$cid}{local};
            $remote = $ctab{$cid}{remote};
            print "rseq $remote->{cseqno} lseq $local->{cseqno}\n";

            if ($remote->{cseqno} == $local->{cseqno}) {
                $rkey = $remote->{c}->{addr} . ':' . $remote->{rtpport};
                $lkey = $local->{c}->{addr} . ':' . $local->{rtpport};
                print "Session: $rkey, $lkey\n";
                #$bykey{$rkey} = $remote;
                $bykey{$lkey} = $local;
                #$byip{$remote->{c}->{addr}} = $remote;
            }
        }
	}else {
        logp('Ninfo', $cnt, $ip_obj, $udp_obj);
        $rkey = $ip_obj->{src_ip} . ':' . $udp_obj->{src_port};
        #print "check by key $rkey $bykey{$rkey}\n";
        if ($bykey{$rkey}) {
            print "key match: $rkey, record\n";
            $rh = $bykey{$rkey}->{cid};
            print "rh = $rh\n";

                # Ripped this RTP packet decoding stuff from Net::SIP::Simple::RTP,
                # I believe this code is (C) Steffen Ullrich, Steffen_Ullrich@genua.de

                my ($buf) = $udp_obj->{data};
                my ($vpxcc,$mpt,$seq,$tstamp,$ssrc) = unpack( 'CCnNN',substr( $buf,0,12,'' ));
                my $version = ($vpxcc & 0xc0) >> 6;
                print "version:$version, seq $seq, ts $tstamp, ssrc $ssrc, mpt $mpt\n";
                # skip csrc headers
                my $cc = $vpxcc & 0x0f;
                substr( $buf,0,4*$cc,'' ) if $cc;

                # skip extension header
                my $xh = $vpxcc & 0x10 ? (unpack( 'nn', substr( $buf,0,4,'' )))[1] : 0;
                substr( $buf,0,4*$xh,'' ) if $xh;

                print "cc: $cc xh $xh\n";

                # ignore padding
                my $padding = $vpxcc & 0x20 ? unpack( 'C', substr($buf,-1,1)) : 0;
                my $payload = $padding ? substr( $buf,0,length($buf)-$padding ): $buf;

            if (! $active{$rh}) {
                open($rh,">$rh") or die "Can't open $rh for write\n";
                binmode($rh);
                $active{$rh}++;
                print $rh $payload;

            }else {
                print $rh $payload;
            }
        }
    }
}

sub logp {
    my ($type, $cnt, $ip_obj, $udp_obj) = @_;
    my ($info) = '';
    if ($type eq 'Sinfo') {
        print LOG "\n------------:\n";
        $info = 'SIP' . ':' . $cnt;
    }
    printf LOG "%12s: %s -> %s, %s\n",
        $info,
        "$ip_obj->{src_ip}:$udp_obj->{src_port}",
        "$ip_obj->{dest_ip}:$udp_obj->{dest_port}", 
        $udp_obj->{len};
    if ($type eq 'Sinfo') {
        print LOG "\n";
    }
}

sub parse_sip {
    my $data = shift;
    my @data = split(/\n/, $data);
    my ($reqres, $status, $maudio);
    my ($branch, $f);
    my %sip;
    my %audio;
    my $body=0;
    my ($key, $field, $value);

    my $line = shift @data;
    $line =~ s///g;
    if ($line =~ /^SIP\/2.0 ([0-9]+) (.+)/) {
        $sip{type} = 'response';
        $sip{code} = $1;
        $sip{status} = $2;
    }else {
        $sip{type} = 'request';
        ($sip{meth}, $sip{what}, $sip{sver}) = split(' ', $line);
    }
    
    foreach $line (@data) {
        $line =~ s///g;
        if ($line =~ /^\s*$/) {
            $body++;
        }
        if ($body > 0) {
            if ($sip{'Content-Type'} =~ /sdp/) {
                if ($line =~ /^m=audio (.+)/ ) {
                    $maudio = $1;
                    (   $sip{rtpport}, 
                        $sip{aproto}, 
                        $sip{rest}
                    ) = split(' ',$maudio);
                    last;
                }
                if ($line =~ /^o=(.+)$/m) {
                    $sip{origin} = $1;
                    my %o;
                    (
                    $o{u},
                    $o{sid},
                    $o{sver},
                    $o{ntype},
                    $o{atype},
                    $o{addr}
                    ) = split(' ',$sip{origin});
                    $sip{o} = \%o;
                }
                if ($line =~ /^c=(.+)$/m) {
                    $sip{connect} = $1;
                    my %c;
                    (
                    $c{ntype},
                    $c{atype},
                    $c{addr}
                    ) = split(' ',$sip{connect});
                    $sip{c} = \%c;
                }
            }else {
                last;
            }
        }else {
            ($field, $value) = split(': ', $line, 2);
            if ($field eq 'Via') {
                my @via = split(/\;/,$value);
                $sip{via}{full} = $value;
                $sip{via}{via} = shift @via;
                foreach my $vline (@via) {
                    if ($line =~ /branch=(.+)\;/) {
                        $sip{via}{branch} = $1;
                    }
                }
            }
            $sip{$field} = $value;
        }
    }
    $sip{cid} = $sip{'Call-ID'};
    foreach $key ('To', 'From') {
        printf LOG "%12s: %s\n", $key, $sip{$key};
    }
    printf LOG "%12s: %s\n", 'via', $sip{via}{via};
    printf LOG "%12s: %s\n", 'via-branch', $sip{via}{branch};
    foreach $key ('type','meth','status','code','Call-ID','rtpport') {
        chomp($sip{$key});
        printf LOG "%12s: %s\n", $key, $sip{$key};
    }

    printf LOG "%12s: %s, %s, %s\n", 'o', $sip{o}->{sid}, $sip{o}->{sver}, $sip{o}->{addr};
    printf LOG "%12s: %s, %s, %s\n", 'c', $sip{c}->{ntype}, $sip{c}->{atype}, $sip{c}->{addr};
    my($cseqno, $cseqtxt) = split(' ', $sip{'CSeq'});
    $sip{cseqno} = $cseqno;
    $sip{cseqtxt} = $cseqtxt;
    printf LOG "%12s: %s, %s\n", 'cseq', $cseqno, $cseqtxt;

    return \%sip;
}

Net::PcapUtils::loop(\&process_pkt, FILTER => 'udp', SNAPLEN => 1500);
