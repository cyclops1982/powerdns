#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;


my $key_name = 'dynupdater.';
my $key = 'efnwQc8ud8iXHuqNuB+xHJ0OJk8HIjb9oAcHd xQqfH9mMLFucywyQM/3YG3i4/9beaA==';
 
# Create the update packet.
my $update = Net::DNS::Update->new('test.com');

# Prerequeste :-)
#$update->push(prerequisite => yxrrset('server1.test.com.')); #QClass == ANY
#$update->push(prerequisite => nxrrset('server1.wtest.com. A')); #QClass == NONE
#$update->push(prerequisite => yxrrset('prereq.yxrrset.wtest.com. A'));
#$update->push(prerequisite => yxdomain('prereq.yxdomain.wtest.com.'));
#$update->push(prerequisite => nxdomain('server1.wtest.com.'));
 
# Add two A records for the name.
my $time = time;
#$update->push(update => rr_del("server3.test.com."));
$update->push(update => rr_add('server3.test.com. 130 A 192.168.1.20'));
#$update->push(update => rr_add("update.add-time.test.com. 120 TXT \"$time\""));

# NS?
#$update->push(update => rr_add('wtest.com. 120 NS nsd.dyn.de.'));
#$update->push(update => rr_add('nsd.wtest.com. 120 A 192.168.1.182'));

# Sign the update packet
# $update->sign_tsig($key_name, $key);
 
# Send the update to the zone's primary master.
my $res = Net::DNS::Resolver->new;
$res->nameservers('127.0.0.2');
$res->port(5300);
 
my $reply = $res->send($update);
 
# Did it work?
if ($reply) {
     if ($reply->header->rcode eq 'NOERROR') {
         print "Update succeeded:", $reply->header->rcode, "\n";
     } else {
         print 'Update failed: ', $reply->header->rcode, "\n";
     }
} else {
     print 'Update failed: ', $res->errorstring, "\n";
}
