#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;


# Create the update packet.
my $update = Net::DNS::Update->new('prof-x.net');
$update->push(prerequisite => nxdomain('prof-x.net'));
#$update->push(update => rr_add('bishop.prof-x.net 18000 A 192.168.1.154'));
#$update->push(update => rr_add('Bishop.prof-x.net 18000 TXT "318188eb1a97d43928ccf8494d4a910c8a"'));
$update->sign_tsig("ddns", "cIASJTQzMXivld680Z2qUA==");

my $res = Net::DNS::Resolver->new;
$res->nameservers('127.0.0.2');
$res->port(5300);
 
my $reply = $res->send($update);
 
if ($reply) {
     if ($reply->header->rcode eq 'NOERROR') {
         print "Update succeeded:", $reply->header->rcode, "\n";
     } else {
         print 'Update failed: ', $reply->header->rcode, "\n";
     }
} else {
     print 'Update failed: ', $res->errorstring, "\n";
}
