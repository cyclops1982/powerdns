#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;

my $update = Net::DNS::Update->new('test.dyndns');
$update->push(prerequisite => yxdomain('host-1.test.dyndns'));
$update->push(update => rr_del('host-1.test.dyndns.'));
$update->push(update => rr_add('host-1.test.dyndns 120 A 192.168.1.1'));


my $res = Net::DNS::Resolver->new;
$res->nameservers($ARGV[0]);
$res->port($ARGV[1]);
 
my $reply = $res->send($update);
 
if ($reply) {
	print "RCODE: ", $reply->header->rcode, "\n";
} else {
	print "ERROR: ", $res->errorstring, "\n";
}
