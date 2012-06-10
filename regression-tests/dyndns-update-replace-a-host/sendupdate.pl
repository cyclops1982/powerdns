#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;

my $update = Net::DNS::Update->new('test.dyndns');
$update->push(prerequisite => yxdomain('host-2.test.dyndns'));
$update->push(update => rr_del('host-2.test.dyndns. A'));
$update->push(update => rr_add('host-2.test.dyndns. 120 A 127.0.0.1'));

my $res = Net::DNS::Resolver->new;
$res->nameservers($ARGV[0]);
$res->port($ARGV[1]);
 
my $reply = $res->send($update);
 
if ($reply) {
	print "RCODE: ", $reply->header->rcode, "\n";
} else {
	print "ERROR: ", $res->errorstring, "\n";
}
