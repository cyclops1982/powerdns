#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;


# Create the update packet.
my $update = Net::DNS::Update->new('test.com');

$update->push(update => rr_del('server3.test.com.'));
$update->push(update => rr_add('server3.test.com. 130 A 192.168.1.23'));
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
