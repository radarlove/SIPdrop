
SIPDrop - Record VoIP Phone Calls via Packet Capture
----------------------------------------------------

Copyright (c) 2012, Richard Liming


Description
-----------

SIPdrop.pl is a tool that can be used for recording VoIP phone calls that
are set up via the Session Initiation Protocal (SIP).  It will provide
a discrete audio file for each call.  SIPdrop also listens for 
instructions on a seperate UDP control channel so you can provide
additional control, such as selective recording by IP address, etc.

Requirements
------------

Since SIPdrop uses packet capture it needs to run in an environment with
access to packets between the target systems.  Typically this means
running it while connected to a switch mirror port, or on a machine 
with a bridged interface, on a central SIP server, or perhaps through ARP 
manipulation.

Overview
--------

SIPdrop.pl functions by listening to network traffic using Perl packet 
capture libraries with a filter for UDP.  If the source or destination port 
is the standard port 5060 for SIP, SIPdrop will parse the packet for all 
header fields and return this as a data structure for further examination.
If the 'Content-type' is 'sdp' (Session Description Protocol) then that body
is further parsed and the SDP information is included in the returned data
structure.

If the SIP data structure contains a SIP 'INVITE' containing SDP connection
data, then SIPdrop will add an entry in an internal hash 'ctab' (call table) 
keyed on the SIP 'Call-Id' (cid) field and named 'remote'.  If later a packet 
arrives with a '200 OK' response that is a reply to an INVITE and contains a 
matching SIP sequence field 'CSeq' then a reference to this SIP data
structure is added to the same 'ctab' table keyed again on 'Call-Id' but
called 'local'.

At this point a check is made that the data from both of these structures
representing a SIP INVITE (remote) and a SIP '200 OK' reply to that invite
have matching 'CSeq' numbers.  If so a new pair of keys is created from
the IP address and SDP media data field, the 'm' field:

::

    m=audio 17394 RTP/AVP 0 8 4 18

These keys are a combination of IP address combined with the RTP audio port 
(17394) specified in the SDP media field; the two values concatenated 
by ':', and these keys are placed into another internal hash called 'bykey'.

Later if a UDP packet arrives with a key (IPaddress+RTP audio port pair) 
matching something a key in the 'bykey' hash, then this is raw audio for
a SIP call and it is saved in a file that is named <Call-Id>@<IPAddress>.
If it the first packet, a new file is created and an entry is added to
another internal data hash called 'active' that represents calls being
actively recorded. Subsequent packets are appended to the file.

Later if a SIP packet arrives with a 'BYE' message, the file is closed and
entries are removed from the 'active' hash.

Invocation
----------

Just run the Perl script::

    ./sipdrop.pl


Control Channel
---------------

The existing code is in transition.  Currently it will record all calls, but
code is nearly in place to select which calls to record.  Since SIPdrop
already sees every UDP packet, the control mechanism is a UDP client that
sends commands to another configurable port.  

The udpclient.pl file is included in this repo, and is just the following
small bit of code to take command line input and pass it over the UDP
control channel to SIPdrop.   

udpclient.pl
------------

::

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


After starting SIPdrop, run udpclient.pl and type commands such as 'quit' to the server.
Four commands are currently implemented in the SIPdrop UDP listener code:
    - quit
    - record <IP>
    - stop <IP>
    - show  # hook to show active recordings.  not implemented

Although 'record' and 'stop' are parsed as they come from the control 
channel and they add and remove entries to and from the %record hash,
the code doesn't currently look at this hash to see if it should record
this call; it just records all calls.

To add the selective recording, just add a check against this %record
hash using the source or dest IP as a key.  If it has a value, then it
must have been sent via the control channel to record that IP, so only
then analyze the packet, otherwise 'next' packet.  Something like::

    $src_ip = $ip_obj->{src_ip}
    next unless ($record{$src_ip}) 

Do this IP filtering after the check to see if it is a packet from the
control server, soos ya don't block your own commands like 'quit'
from being seen ;)



