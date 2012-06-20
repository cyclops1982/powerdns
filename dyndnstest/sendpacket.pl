#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;


# Create the update packet.
my $update = Net::DNS::Update->new('test.dyndns.');


$update->push(prerequisite => yxrrset('multi.test.dyndns. 600 A 127.0.0.1'));
$update->push(prerequisite => yxrrset('multi.test.dyndns. 600 A 127.0.0.2'));
$update->push(prerequisite => yxrrset('multi.test.dyndns. 600 A 127.0.0.3'));

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
