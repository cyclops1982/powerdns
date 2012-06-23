#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;

my $update = Net::DNS::Update->new('test.dyndns');
$update->push(prerequisite => yxdomain('test.dyndns'));
$update->push(prerequisite => nxrrset('delete-add.test.dyndns'));
$update->push(update => rr_add('delete-add.test.dyndns. 3600 A 127.0.0.108'));
$update->push(update => rr_add('delete-add.test.dyndns. 3600 TXT "Should be gone after a while"'));


my $res = Net::DNS::Resolver->new;
$res->nameservers($ARGV[0]);
$res->port($ARGV[1]);
 
my $reply = $res->send($update);
 
if ($reply) {
	print "RCODE: ", $reply->header->rcode, "\n";
} else {
	print "ERROR: ", $res->errorstring, "\n";
}
