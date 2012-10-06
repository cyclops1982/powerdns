/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "packetcache.hh"
#include "utility.hh"
#include "base32.hh"
#include "base64.hh"
#include <string>
#include <sys/types.h>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "resolver.hh"
#include "communicator.hh"
#include "dnsproxy.hh"

#if 0
#undef DLOG
#define DLOG(x) x
#endif 

extern StatBag S;
extern PacketCache PC;  
extern CommunicatorClass Communicator;
extern DNSProxy *DP;

AtomicCounter PacketHandler::s_count;
extern string s_programname;

PacketHandler::PacketHandler():B(s_programname)
{
  ++s_count;
  d_doFancyRecords = (::arg()["fancy-records"]!="no");
  d_doRecursion= ::arg().mustDo("recursor");
  d_logDNSDetails= ::arg().mustDo("log-dns-details");
  d_doIPv6AdditionalProcessing = ::arg().mustDo("do-ipv6-additional-processing");
  string fname= ::arg()["lua-prequery-script"];
  if(fname.empty())
  {
    d_pdl = NULL;
  }
  else
  {
    d_pdl = new AuthLua(fname);
  }

}

DNSBackend *PacketHandler::getBackend()
{
  return &B;
}

PacketHandler::~PacketHandler()
{
  --s_count;
  DLOG(L<<Logger::Error<<"PacketHandler destructor called - "<<s_count<<" left"<<endl);
}

void PacketHandler::addRootReferral(DNSPacket* r)
{  
  // nobody reads what we output, but it appears to be the magic that shuts some nameservers up
  static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
        	     "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  static char templ[40];
  strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);

  // add . NS records
  DNSResourceRecord rr;
  rr.qtype=QType::NS;
  rr.ttl=518400;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  
  for(char c='a';c<='m';++c) {
    *templ=c;
    rr.content=templ;
    r->addRecord(rr);
  }

  if(pdns_iequals(::arg()["send-root-referral"], "lean"))
     return;

  // add the additional stuff
  
  rr.ttl=3600000;
  rr.qtype=QType::A;
  rr.d_place=DNSResourceRecord::ADDITIONAL;

  for(char c='a';c<='m';++c) {
    *templ=c;
    rr.qname=templ;
    rr.content=ips[c-'a'];
    r->addRecord(rr);
  }
}

int PacketHandler::findMboxFW(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  bool wedoforward=false;

  SOAData sd;
  int zoneId;
  if(!getAuth(p, &sd, target, &zoneId))
    return false;

  B.lookup(QType(QType::MBOXFW),string("%@")+target,p, zoneId);
      
  while(B.get(rr))
    wedoforward=true;

  if(wedoforward) {
    r->clearRecords();
    rr.content=::arg()["smtpredirector"];
    rr.priority=25;
    rr.ttl=7200;
    rr.qtype=QType::MX;
    rr.qname=target;
    
    r->addRecord(rr);
  }

  return wedoforward;
}

int PacketHandler::findUrl(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;

  bool found=false;
      
  B.lookup(QType(QType::URL),target,p); // search for a URL before we search for an A
        
  while(B.get(rr)) {
    if(!found) 
      r->clearRecords();
    found=true;
    DLOG(L << "Found a URL!" << endl);
    rr.content=::arg()["urlredirector"];
    rr.qtype=QType::A; 
    rr.qname=target;
          
    r->addRecord(rr);
  }  

  if(found) 
    return 1;

  // now try CURL
  
  B.lookup(QType(QType::CURL),target,p); // search for a URL before we search for an A
      
  while(B.get(rr)) {
    if(!found) 
      r->clearRecords();
    found=true;
    DLOG(L << "Found a CURL!" << endl);
    rr.content=::arg()["urlredirector"];
    rr.qtype=1; // A
    rr.qname=target;
    rr.ttl=300;
    r->addRecord(rr);
  }  

  if(found)
    return found;
  return 0;
}

/** Returns 0 if nothing was found, -1 if an error occured or 1 if the search
    was satisfied */
int PacketHandler::doFancyRecords(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  if(p->qtype.getCode()==QType::MX)  // check if this domain has smtp service from us
    return findMboxFW(p,r,target);
  
  if(p->qtype.getCode()==QType::A)   // search for a URL record for an A
    return findUrl(p,r,target);
  return 0;
}

/** This adds DNSKEY records. Returns true if one was added */
bool PacketHandler::addDNSKEY(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  DNSResourceRecord rr;
  bool haveOne=false;
  DNSSECPrivateKey dpk;

  DNSSECKeeper::keyset_t keyset = d_dk.getKeys(p->qdomain);
  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
    rr.qtype=QType::DNSKEY;
    rr.ttl=sd.default_ttl;
    rr.qname=p->qdomain;
    rr.content=value.first.getDNSKEY().getZoneRepresentation();
    rr.auth=true;
    r->addRecord(rr);
    haveOne=true;
  }
  return haveOne;
}


/** This adds NSEC3PARAM records. Returns true if one was added */
bool PacketHandler::addNSEC3PARAM(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  DNSResourceRecord rr;

  NSEC3PARAMRecordContent ns3prc;
  if(d_dk.getNSEC3PARAM(p->qdomain, &ns3prc)) {
    rr.qtype=QType::NSEC3PARAM;
    rr.ttl=sd.default_ttl;
    rr.qname=p->qdomain;
    ns3prc.d_flags = 0; // the NSEC3PARAM 'flag' is defined to always be zero in RFC5155.
    rr.content=ns3prc.getZoneRepresentation(); 
    rr.auth = true;
    r->addRecord(rr);
    return true;
  }
  return false;
}


/** This catches version requests. Returns 1 if it was handled, 0 if it wasn't */
int PacketHandler::doVersionRequest(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  
  // modes: anonymous, powerdns only, full, spoofed
  const string mode=::arg()["version-string"];
  
  if(p->qclass == QClass::CHAOS && p->qtype.getCode()==QType::TXT && target=="version.bind") {// TXT
    if(mode.empty() || mode=="full") 
      rr.content="Served by POWERDNS "VERSION" $Id$";
    else if(mode=="anonymous") {
      r->setRcode(RCode::ServFail);
      return 1;
    }
    else if(mode=="powerdns")
      rr.content="Served by PowerDNS - http://www.powerdns.com";
    else 
      rr.content=mode;

    rr.ttl=5;
    rr.qname=target;
    rr.qtype=QType::TXT; 
    rr.qclass=QClass::CHAOS; 
    r->addRecord(rr);
    
    return 1;
  }
  return 0;
}

/** Determines if we are authoritative for a zone, and at what level */
bool PacketHandler::getAuth(DNSPacket *p, SOAData *sd, const string &target, int *zoneId)
{
  string subdomain(target);
  do {
    if( B.getSOA( subdomain, *sd, p ) ) {
      if(p->qtype.getCode() == QType::DS && pdns_iequals(subdomain, target)) 
        continue; // A DS question is never answered from the apex, go one zone upwards 
      
      sd->qname = subdomain;
      if(zoneId)
        *zoneId = sd->domain_id;
      return true;
    }
  }
  while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return false;
}

vector<DNSResourceRecord> PacketHandler::getBestReferralNS(DNSPacket *p, SOAData& sd, const string &target)
{
  vector<DNSResourceRecord> ret;
  DNSResourceRecord rr;
  string subdomain(target);
  do {
    if(subdomain == sd.qname) // stop at SOA
      break;
    B.lookup(QType(QType::NS), subdomain, p, sd.domain_id);
    while(B.get(rr)) {
      ret.push_back(rr); // this used to exclude auth NS records for some reason
    }
    if(!ret.empty())
      return ret;
  } while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}

// Return best matching wildcard or next closer name
bool PacketHandler::getBestWildcard(DNSPacket *p, SOAData& sd, const string &target, string &wildcard, vector<DNSResourceRecord>* ret)
{
  ret->clear();
  DNSResourceRecord rr;
  string subdomain(target);
  bool haveSomething=false;

  wildcard=subdomain;
  while ( chopOff( subdomain ) && !haveSomething ) {
    B.lookup(QType(QType::ANY), "*."+subdomain, p, sd.domain_id);
    while(B.get(rr)) {
      if(rr.qtype == p->qtype ||rr.qtype.getCode() == QType::CNAME || (p->qtype.getCode() == QType::ANY && rr.qtype.getCode() != QType::RRSIG))
        ret->push_back(rr);
      wildcard="*."+subdomain;
      haveSomething=true;
    }

    if ( subdomain == sd.qname || haveSomething ) // stop at SOA or result
      break;

    B.lookup(QType(QType::ANY), subdomain, p, sd.domain_id);
    if (B.get(rr)) {
      DLOG(L<<"No wildcard match, ancestor exists"<<endl);
      while (B.get(rr)) ;
      break;
    }
    wildcard=subdomain;
  }

  return haveSomething;
}

/** dangling is declared true if we were unable to resolve everything */
int PacketHandler::doAdditionalProcessingAndDropAA(DNSPacket *p, DNSPacket *r, const SOAData& soadata)
{
  DNSResourceRecord rr;
  SOAData sd;
  sd.db=0;

  if(p->qtype.getCode()!=QType::AXFR) { // this packet needs additional processing
    vector<DNSResourceRecord *> arrs=r->getAPRecords();
    if(arrs.empty()) 
      return 1;

    DLOG(L<<Logger::Warning<<"This packet needs additional processing!"<<endl);

    vector<DNSResourceRecord> crrs;

    for(vector<DNSResourceRecord *>::const_iterator i=arrs.begin(); i!=arrs.end(); ++i) 
      crrs.push_back(**i);

    // we now have a copy, push_back on packet might reallocate!
    for(vector<DNSResourceRecord>::const_iterator i=crrs.begin(); i!=crrs.end(); ++i) {
      if(r->d.aa && !i->qname.empty() && i->qtype.getCode()==QType::NS && !B.getSOA(i->qname,sd,p)) { // drop AA in case of non-SOA-level NS answer, except for root referral
        r->setA(false);
        //	i->d_place=DNSResourceRecord::AUTHORITY; // XXX FIXME
      }

      string content = stripDot(i->content);

      QType qtypes[2];
      qtypes[0]="A"; qtypes[1]="AAAA";
      for(int n=0 ; n < d_doIPv6AdditionalProcessing + 1; ++n) {
        if (i->qtype.getCode()==QType::SRV) {
          vector<string>parts;
          stringtok(parts, content);
          if (parts.size() >= 3) {
            B.lookup(qtypes[n],parts[2],p);
          }
          else
            continue;
        }
        else {
          B.lookup(qtypes[n], content, p);
        }
        while(B.get(rr)) {
          if(rr.domain_id!=i->domain_id && ::arg()["out-of-zone-additional-processing"]=="no") {
            DLOG(L<<Logger::Warning<<"Not including out-of-zone additional processing of "<<i->qname<<" ("<<rr.qname<<")"<<endl);
            continue; // not adding out-of-zone additional data
          }
          if(rr.auth && !endsOn(rr.qname, soadata.qname)) // don't sign out of zone data using the main key 
            rr.auth=false;
          rr.d_place=DNSResourceRecord::ADDITIONAL;
          r->addRecord(rr);
        }
      }
    }
  }
  return 1;
}


void PacketHandler::emitNSEC(const std::string& begin, const std::string& end, const std::string& toNSEC, const SOAData& sd, DNSPacket *r, int mode)
{
  // <<"We should emit '"<<begin<<"' - ('"<<toNSEC<<"') - '"<<end<<"'"<<endl;
  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);
  if(sd.qname == begin)
    nrc.d_set.insert(QType::DNSKEY);

  DNSResourceRecord rr;
  B.lookup(QType(QType::ANY), begin);
  while(B.get(rr)) {
    if(rr.domain_id == sd.domain_id && (rr.qtype.getCode() == QType::NS || rr.auth))
      nrc.d_set.insert(rr.qtype.getCode());    
  }
  
  nrc.d_next=end;

  rr.qname=begin;
  rr.ttl = sd.default_ttl;
  rr.qtype=QType::NSEC;
  rr.content=nrc.getZoneRepresentation();
  rr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;
  
  r->addRecord(rr);
}

void emitNSEC3(DNSBackend& B, const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
//  cerr<<"We should emit NSEC3 '"<<toLower(toBase32Hex(begin))<<"' - ('"<<toNSEC3<<"') - '"<<toLower(toBase32Hex(end))<<"' (unhashed: '"<<unhashed<<"')"<<endl;
  NSEC3RecordContent n3rc;
  n3rc.d_salt=ns3prc.d_salt;
  n3rc.d_flags = ns3prc.d_flags;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_algorithm = 1; // SHA1, fixed in PowerDNS for now

  DNSResourceRecord rr;
  if(!unhashed.empty()) {
    B.lookup(QType(QType::ANY), unhashed);
    while(B.get(rr)) {
      if(rr.domain_id == sd.domain_id && rr.qtype.getCode()) // skip out of zone data and empty non-terminals
        n3rc.d_set.insert(rr.qtype.getCode());
    }

    if(unhashed == sd.qname) {
      n3rc.d_set.insert(QType::NSEC3PARAM);
      n3rc.d_set.insert(QType::DNSKEY);
    }
  }

  if (n3rc.d_set.size())
    n3rc.d_set.insert(QType::RRSIG);
  
  n3rc.d_nexthash=end;

  rr.qname=dotConcat(toLower(toBase32Hex(begin)), sd.qname);
  rr.ttl = sd.default_ttl;
  rr.qtype=QType::NSEC3;
  rr.content=n3rc.getZoneRepresentation();
  rr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;
  
  r->addRecord(rr);
}

void PacketHandler::emitNSEC3(const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
  ::emitNSEC3(B, ns3prc, sd, unhashed, begin, end, toNSEC3, r, mode);
  
}

/*
   mode 0 = No Data Responses, QTYPE is not DS
   mode 1 = No Data Responses, QTYPE is DS
   mode 2 = Wildcard No Data Responses
   mode 3 = Wildcard Answer Responses
   mode 4 = Name Error Responses
   mode 5 = ANY or direct NSEC request
*/
void PacketHandler::addNSECX(DNSPacket *p, DNSPacket *r, const string& target, const string& target3, const string& auth, int mode)
{
  NSEC3PARAMRecordContent ns3rc;
  // cerr<<"Doing NSEC3PARAM lookup for '"<<auth<<"', "<<p->qdomain<<"|"<<p->qtype.getName()<<": ";
  bool narrow;
  if(d_dk.getNSEC3PARAM(auth, &ns3rc, &narrow))  {
    // cerr<<"Present, narrow="<<narrow<<endl;
    addNSEC3(p, r, target3, auth, ns3rc, narrow, mode);
  }
  else {
    // cerr<<"Not present"<<endl;
    addNSEC(p, r, target, auth, mode);
  }
}

static void incrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;
    
  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    ++c;
    raw[pos] = (char) c;
    if(c)
      break;
  }
}

static void decrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;
    
  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    --c;
    raw[pos] = (char) c;
    if(c != 0xff)
      break;
  }
}


bool getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, string& unhashed, string& before, string& after)
{
  bool ret;
  if(narrow) { // nsec3-narrow
    ret=true;
    before=hashed;
    if(decrement) {
      decrementHash(before);
      unhashed.clear();
    }
    after=hashed;
    incrementHash(after);
  }
  else {
    ret=db->getBeforeAndAfterNamesAbsolute(id, toLower(toBase32Hex(hashed)), unhashed, before, after);
    before=fromBase32Hex(before);
    after=fromBase32Hex(after);
  }
  // cerr<<"rgetNSEC3Hashes: "<<hashed<<", "<<unhashed<<", "<<before<<", "<<after<<endl;
  return ret;
}

void PacketHandler::addNSEC3(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, const NSEC3PARAMRecordContent& ns3rc, bool narrow, int mode)
{
  // L<<"mode="<<mode<<" target="<<target<<" auth="<<auth<<endl;
  
  SOAData sd;
  sd.db = (DNSBackend*)-1;
  if(!B.getSOA(auth, sd)) {
    // cerr<<"Could not get SOA for domain in NSEC3\n";
    return;
  }
  // cerr<<"salt in ph: '"<<makeHexDump(ns3rc.d_salt)<<"', narrow="<<narrow<<endl;
  string unhashed, hashed, before, after;
  string closest(target);
  
  if (mode == 2 || mode == 3 || mode == 4) {
    chopOff(closest);
  }
  
  if (mode == 1) {
    DNSResourceRecord rr;
    while( chopOff( closest ) && (closest != sd.qname))  { // stop at SOA
      B.lookup(QType(QType::ANY), closest, p, sd.domain_id);
      if (B.get(rr)) {
        while(B.get(rr));
        break;
      }
    }
  }
  
  // add matching NSEC3 RR
  if (mode != 3) {
    if (mode == 0 || mode == 5) {
      unhashed=target;
    }
    else {
      unhashed=closest;
    }

    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    // L<<"1 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl;
  
    getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after);
    DLOG(L<<"Done calling for matching, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3(ns3rc, sd, unhashed, before, after, target, r, mode);
  }

  // add covering NSEC3 RR
  if (mode != 0 && mode != 5) {
    string next(p->qdomain);
    do {
      unhashed=next;
    }
    while( chopOff( next ) && !pdns_iequals(next, closest));

    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    // L<<"2 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl;

    getNSEC3Hashes(narrow, sd.db,sd.domain_id,  hashed, true, unhashed, before, after);
    DLOG(L<<"Done calling for covering, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
  }
  
  // wildcard denial
  if (mode == 4) {
    unhashed=dotConcat("*", closest);

    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    // L<<"3 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl;
    
    getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, true, unhashed, before, after);
    DLOG(L<<"Done calling for '*', hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
  }
}

void PacketHandler::addNSEC(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, int mode)
{
  if(!p->d_dnssecOk)
    return;
  
  DLOG(L<<"Should add NSEC covering '"<<target<<"' from zone '"<<auth<<"', mode = "<<mode<<endl);
  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer

  if(auth.empty()) {
    getAuth(p, &sd, target, 0);
  }
  else if(!B.getSOA(auth, sd)) {
    DLOG(L<<"Could not get SOA for domain"<<endl);
    return;
  }

  string before,after;
  //cerr<<"Calling getBeforeandAfter!"<<endl;

  if (mode == 2) {
    // wildcard NO-DATA
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, p->qdomain, before, after);
    emitNSEC(before, after, target, sd, r, mode);
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after);
  }
  else {
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after);
  }
  emitNSEC(before, after, target, sd, r, mode);
  
  if (mode == 4) {
      // this one does wildcard denial, if applicable
      sd.db->getBeforeAndAfterNames(sd.domain_id, auth, auth, before, after);
      emitNSEC(auth, after, auth, sd, r, mode);
  }

  return;
}

/* Semantics:
   
- only one backend owns the SOA of a zone
- only one AXFR per zone at a time - double startTransaction should fail
- backends need to implement transaction semantics


How BindBackend would implement this:
   startTransaction makes a file 
   feedRecord sends everything to that file 
   commitTransaction moves that file atomically over the regular file, and triggers a reload
   rollbackTransaction removes the file


How PostgreSQLBackend would implement this:
   startTransaction starts a sql transaction, which also deletes all records
   feedRecord is an insert statement
   commitTransaction commits the transaction
   rollbackTransaction aborts it

How MySQLBackend would implement this:
   (good question!)
   
*/     

int PacketHandler::trySuperMaster(DNSPacket *p)
{
  if(p->d_tcp)
  {
    // do it right now if the client is TCP
    // rarely happens
    return trySuperMasterSynchronous(p);
  }
  else
  {
    // queue it if the client is on UDP
    Communicator.addTrySuperMasterRequest(p);
    return 0;
  }
}

int PacketHandler::trySuperMasterSynchronous(DNSPacket *p)
{
  Resolver::res_t nsset;
  try {
    Resolver resolver;
    uint32_t theirserial;
    resolver.getSoaSerial(p->getRemote(),p->qdomain, &theirserial);    
    resolver.resolve(p->getRemote(), p->qdomain.c_str(), QType::NS, &nsset);
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Error resolving SOA or NS for "<<p->qdomain<<" at: "<< p->getRemote() <<": "<<re.reason<<endl;
    return RCode::ServFail;
  }

  string account;
  DNSBackend *db;
  if(!B.superMasterBackend(p->getRemote(), p->qdomain, nsset, &account, &db)) {
    L<<Logger::Error<<"Unable to find backend willing to host "<<p->qdomain<<" for potential supermaster "<<p->getRemote()<<endl;
    return RCode::Refused;
  }
  try {
    db->createSlaveDomain(p->getRemote(),p->qdomain,account);
  }
  catch(AhuException& ae) {
    L<<Logger::Error<<"Database error trying to create "<<p->qdomain<<" for potential supermaster "<<p->getRemote()<<": "<<ae.reason<<endl;
    return RCode::ServFail;
  }
  Communicator.addSuckRequest(p->qdomain, p->getRemote());  
  L<<Logger::Warning<<"Created new slave zone '"<<p->qdomain<<"' from supermaster "<<p->getRemote()<<", queued axfr"<<endl;
  return RCode::NoError;
}

// Implement section 3.2.1 and 3.2.2 of RFC2136
int PacketHandler::updatePrerequisitesCheck(const DNSRecord *rr, DomainInfo *di) {
  if (rr->d_ttl != 0)
    return RCode::FormErr;

  // 3.2.1 and 3.2.2 check content length.
  if ( (rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_clen != 0)
    return RCode::FormErr;

  string rLabel = stripDot(rr->d_label);

  bool foundRecord=false;
  DNSResourceRecord rec;
  di->backend->lookup(QType(QType::ANY), rLabel);
  while(di->backend->get(rec)) {
    if (!rec.qtype.getCode())
      continue;
    if ((rr->d_type != QType::ANY && rec.qtype == rr->d_type) || rr->d_type == QType::ANY)
      foundRecord=true;
  }

  // Section 3.2.1        
  if (rr->d_class == QClass::ANY && !foundRecord) { 
    if (rr->d_type == QType::ANY) 
      return RCode::NXDomain;
    if (rr->d_type != QType::ANY)
      return RCode::NXRRSet;
  } 

  // Section 3.2.2
  if (rr->d_class == QClass::NONE && foundRecord) {
    if (rr->d_type == QType::ANY)
      return RCode::YXDomain;
    if (rr->d_type != QType::ANY)
      return RCode::YXRRSet;
  }

  return RCode::NoError;
}


// Method implements section 3.4.1 of RFC2136
int PacketHandler::updatePrescanCheck(const DNSRecord *rr) {
  // The RFC stats that d_class != ZCLASS, but we only support the IN class.
  if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY) 
    return RCode::FormErr;

  QType qtype = QType(rr->d_type);

  if (! qtype.isSupportedType())
    return RCode::FormErr;

  if ((rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_ttl != 0)
    return RCode::FormErr;

  if (rr->d_class == QClass::ANY && rr->d_clen != 0)
    return RCode::FormErr;
  
  if (qtype.isMetadataType())
      return RCode::FormErr;

  if (rr->d_class != QClass::ANY && qtype.getCode() == QType::ANY)
    return RCode::FormErr;

  return RCode::NoError;
}

// Implements section 3.4.2 of RFC2136
uint16_t PacketHandler::performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool narrow, bool haveNSEC3, const NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial) {
  DNSResourceRecord rec;
  uint16_t updatedRecords = 0, deletedRecords = 0, insertedRecords = 0;

  string rLabel = stripDot(rr->d_label);

  if (rr->d_class == QClass::IN) { // 3.4.2.2, Add/update records.
    DLOG(L<<msgPrefix<<"Add/Update record (QClass == IN)"<<endl);
    bool foundRecord=false;
    set<string> delnonterm;
    vector<pair<DNSResourceRecord, DNSResourceRecord> > recordsToUpdate;
    di->backend->lookup(QType(QType::ANY), rLabel);
    while (di->backend->get(rec)) {
      if (!rec.qtype.getCode())
        delnonterm.insert(rec.qname); // we're inserting a record which is a ENT, so we must delete that ENT
      if (rr->d_type == QType::SOA && rec.qtype == QType::SOA) {
        foundRecord = true;
        DNSResourceRecord newRec = rec;
        newRec.setContent(rr->d_content->getZoneRepresentation());
        newRec.ttl = rr->d_ttl;
        SOAData sdOld, sdUpdate;
        fillSOAData(rec.content, sdOld);
        fillSOAData(newRec.content, sdUpdate);
        if (rfc1982LessThan(sdOld.serial, sdUpdate.serial)) {
          recordsToUpdate.push_back(make_pair(rec, newRec));
          *updatedSerial = true;
        }
        else
          L<<Logger::Notice<<msgPrefix<<"Provided serial ("<<sdUpdate.serial<<") is older than the current serial ("<<sdOld.serial<<"), ignoring SOA update."<<endl;
      } else if (rr->d_type == QType::CNAME && rec.qtype == QType::CNAME) { // If the update record is a cname, we update that cname. 
        foundRecord = true;
        DNSResourceRecord newRec = rec;
        newRec.ttl = rr->d_ttl;
        newRec.setContent(rr->d_content->getZoneRepresentation());
        recordsToUpdate.push_back(make_pair(rec, newRec));
      } else if (rec.qtype == rr->d_type) {
        string content = rr->d_content->getZoneRepresentation();
        if (rec.getZoneRepresentation() == content) {
          foundRecord=true;
          DNSResourceRecord newRec = rec;
          newRec.ttl = rr->d_ttl; // If content matches, we can only update the TTL.
          recordsToUpdate.push_back(make_pair(rec, newRec));
        }
      }
    }
   // Update the records
   for(vector<pair<DNSResourceRecord, DNSResourceRecord> >::const_iterator i=recordsToUpdate.begin(); i!=recordsToUpdate.end(); ++i){
      di->backend->updateRecord(i->first, i->second);
      L<<Logger::Notice<<msgPrefix<<"Updating record "<<i->first.qname<<"|"<<i->first.qtype.getName()<<endl;
      updatedRecords++;
    }
  

    // If the record was not replaced, we insert it.
    if (! foundRecord) {
      DNSResourceRecord newRec(*rr);
      newRec.domain_id = di->id;
      L<<Logger::Notice<<msgPrefix<<"Adding record "<<newRec.qname<<"|"<<newRec.qtype.getName()<<endl;
      di->backend->feedRecord(newRec);
      insertedRecords++;
    }
    
    // The next section will fix order and Auth fields and insert ENT's 
    if (insertedRecords > 0) {
      string shorter(rLabel);
      bool auth=true;

      set<string> insnonterm;
      if (shorter != di->zone && rr->d_type != QType::DS) {
        do {
          if (shorter == di->zone)
            break;

          bool foundShorter = false;
          di->backend->lookup(QType(QType::ANY), shorter);
          while (di->backend->get(rec)) {
            if (rec.qname != rLabel)
              foundShorter = true;
            if (rec.qtype == QType::NS)
              auth=false;
          }
          if (!foundShorter && shorter != rLabel && shorter != di->zone)
            insnonterm.insert(shorter);

        } while(chopOff(shorter));
      }


      if(haveNSEC3)
      {
        string hashed;
        if(!narrow) 
          hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, rLabel)));
        
        di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, rLabel, hashed, auth);
        if(!auth || rr->d_type == QType::DS)
        {
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rLabel, "NS");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rLabel, "A");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rLabel, "AAAA");
        }
      }
      else // NSEC
      {
        di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, rLabel, auth);
        if(!auth || rr->d_type == QType::DS)
        {
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rLabel, "A");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rLabel, "AAAA");
        }
      }
      // If we insert an NS, all the records below it become non auth - so, we're inserting a delegate.
      // Auth can only be false when the rLabel is not the zone 
      if (auth == false && rr->d_type == QType::NS) {
        DLOG(L<<msgPrefix<<"Going to fix auth flags below "<<rLabel<<endl);
        vector<string> qnames;
        di->backend->listSubZone(rLabel, di->id);
        while(di->backend->get(rec)) {
          if (rec.qtype.getCode() && rec.qtype.getCode() != QType::DS) // Skip ENT and DS records.
            qnames.push_back(rec.qname);
        }
        for(vector<string>::const_iterator qname=qnames.begin(); qname != qnames.end(); ++qname) {
          if(haveNSEC3)  {
            string hashed;
            if(!narrow) 
              hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *qname)));
        
            di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *qname, hashed, auth);
            di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "NS");
          }
          else // NSEC
            di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, *qname, auth);

          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "AAAA");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "A");
        }
      }

      //Insert and delete ENT's
      if (insnonterm.size() > 0 || delnonterm.size() > 0) {
        DLOG(L<<msgPrefix<<"Updating ENT records"<<endl);
        di->backend->updateEmptyNonTerminals(di->id, di->zone, insnonterm, delnonterm, false);
        for (set<string>::const_iterator i=insnonterm.begin(); i!=insnonterm.end(); i++) {
          string hashed;
          if(haveNSEC3)
          {
            string hashed;
            if(!narrow) 
              hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *i)));
            di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *i, hashed, false);
          }
        }
      }
    }
  } // rr->d_class == QClass::IN



  // The following section deals with the removal of records. When the class is ANY, all records of 
  // that name (and/or type) are deleted. When the type is NONE, the RDATA must match as well.
  // There are special cases for SOA and NS records to ensure the zone will remain operational.
  //Section 3.4.2.3: Delete RRs based on name and (if provided) type, but never delete NS or SOA at the zone apex.
  vector<DNSResourceRecord> recordsToDelete;
  if (rr->d_class == QClass::ANY) {
    DLOG(L<<msgPrefix<<"Deleting records (QClass == ANY)"<<endl);
    if (! (rLabel == di->zone && (rr->d_type == QType::SOA || rr->d_type == QType::NS) ) ) {
      di->backend->lookup(QType(QType::ANY), rLabel);
      while (di->backend->get(rec)) {
        if (rec.qtype.getCode() && (rr->d_type == QType::ANY || rr->d_type == rec.qtype.getCode()))
          recordsToDelete.push_back(rec);
      }
    }
  }

  // Section 3.4.2.4, Delete a specific record that matches name, type and rdata
  // again there are specific with some specifics for NS/SOA records. Never delete SOA and never remove
  // the last NS from the zone.
  if (rr->d_class == QClass::NONE && rr->d_type != QType::SOA) { // never remove SOA.
    DLOG(L<<msgPrefix<<"Deleting records (QClass == NONE && type != SOA)"<<endl);
    if (rLabel == di->zone && rr->d_type == QType::NS) { // special condition for apex NS
      int nsCount=0;
      vector<DNSResourceRecord> tmpDel;
      di->backend->lookup(QType(QType::NS), rLabel);
      while(di->backend->get(rec)) {
        nsCount++;
        if (rec.qtype == rr->d_type && rec.getZoneRepresentation() == rr->d_content->getZoneRepresentation())
          tmpDel.push_back(rec); 
      }
      if (nsCount > 1) { // always keep one remaining NS at the apex.
        for(vector<DNSResourceRecord>::const_iterator rtd=tmpDel.begin(); rtd!=tmpDel.end(); rtd++){
          recordsToDelete.push_back(*rtd);
        }
      } 
    } else {
      di->backend->lookup(QType(QType::ANY), rLabel);
      while(di->backend->get(rec)) {
        if (rec.qtype.getCode() && rec.qtype == rr->d_type && rec.getZoneRepresentation() == rr->d_content->getZoneRepresentation()) 
          recordsToDelete.push_back(rec);
      }
    }
  }

  if (recordsToDelete.size()) {
    // Perform removes on the backend and fix auth/ordername
    for(vector<DNSResourceRecord>::const_iterator recToDelete=recordsToDelete.begin(); recToDelete!=recordsToDelete.end(); ++recToDelete){
      L<<Logger::Notice<<msgPrefix<<"Deleting record "<<recToDelete->qname<<"|"<<recToDelete->qtype.getName()<<endl;
      di->backend->removeRecord(*recToDelete);
      deletedRecords++;

      if (recToDelete->qtype.getCode() == QType::NS && recToDelete->qname != di->zone) {
        vector<string> changeAuth;
        di->backend->listSubZone(recToDelete->qname, di->id);
        while (di->backend->get(rec)) {
          if (rec.qtype.getCode()) // skip ENT records
            changeAuth.push_back(rec.qname);
        }
        for (vector<string>::const_iterator changeRec=changeAuth.begin(); changeRec!=changeAuth.end(); ++changeRec) {
          if(haveNSEC3)  {
            string hashed;
            if(!narrow) 
              hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *changeRec)));
        
            di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *changeRec, hashed, true);
          }
          else // NSEC
            di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, *changeRec, true);
        }
      }
    }

    // Fix ENT records.
    // We must check if we have a record below the current level and if we removed the 'last' record
    // on that level. If so, we must insert an ENT record.
    // We take extra care here to not 'include' the record that we just deleted. Some backends will still return it.
    set<string> insnonterm, delnonterm;
    bool foundDeeper = false, foundOther = false;
    di->backend->listSubZone(rLabel, di->id);
    while (di->backend->get(rec)) {
      if (rec.qname == rLabel && !count(recordsToDelete.begin(), recordsToDelete.end(), rec))
        foundOther = true;
      if (rec.qname != rLabel)
        foundDeeper = true;
    }

    if (foundDeeper && !foundOther) {
      insnonterm.insert(rLabel);
    } else if (!foundOther) {
      // If we didn't have to insert an ENT, we might have deleted a record at very deep level
      // and we must then clean up the ENT's above the deleted record.
      string shorter(rLabel);
      do {
        bool foundRealRR=false;
        if (shorter == di->zone)
          break;
        // The reason for a listSubZone here is because might go up the tree and find the root ENT of another branch
        // consider these non ENT-records:
        // a.b.c.d.e.test.com
        // a.b.d.e.test.com
        // if we delete a.b.c.d.e.test.com, we go up to d.e.test.com and then find a.b.d.e.test.com
        // At that point we can stop deleting ENT's because the tree is in tact again.
        di->backend->listSubZone(shorter, di->id);
        while (di->backend->get(rec)) {
          if (rec.qtype.getCode())
            foundRealRR=true;
        }
        if (!foundRealRR)
          delnonterm.insert(shorter);
        else
          break; // we found a real record - tree is ok again.
      }while(chopOff(shorter));
    }

    if (insnonterm.size() > 0 || delnonterm.size() > 0) {
      DLOG(L<<msgPrefix<<"Updating ENT records"<<endl);
      di->backend->updateEmptyNonTerminals(di->id, di->zone, insnonterm, delnonterm, false);
      for (set<string>::const_iterator i=insnonterm.begin(); i!=insnonterm.end(); i++) {
        string hashed;
        if(haveNSEC3)
        {
          string hashed;
          if(!narrow) 
            hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *i)));
          di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *i, hashed, true);
        }
      }
    }
  }

  L<<Logger::Notice<<msgPrefix<<"Added "<<insertedRecords<<"; Updated: "<<updatedRecords<<"; Deleted:"<<deletedRecords<<endl;

  return updatedRecords + deletedRecords + insertedRecords;
}

int PacketHandler::processUpdate(DNSPacket *p) {
  if (::arg().mustDo("disable-rfc2136"))
    return RCode::Refused;
  
  string msgPrefix="UPDATE from " + p->getRemote() + " for " + p->qdomain + ": ";
  L<<Logger::Info<<msgPrefix<<"Processing started."<<endl;

  // Check permissions - IP based
  vector<string> allowedRanges;
  B.getDomainMetadata(p->qdomain, "ALLOW-2136-FROM", allowedRanges);
  if (! ::arg()["allow-2136-from"].empty()) 
    stringtok(allowedRanges, ::arg()["allow-2136-from"], ", \t" );

  NetmaskGroup ng;
  for(vector<string>::const_iterator i=allowedRanges.begin(); i != allowedRanges.end(); i++)
    ng.addMask(*i);
    
  if ( ! ng.match(&p->d_remote)) {
    L<<Logger::Error<<msgPrefix<<"Remote not listed in allow-2136-from or domainmetadata. Sending REFUSED"<<endl;
    return RCode::Refused;
  }


  // Check permissions - TSIG based.
  vector<string> tsigKeys;
  B.getDomainMetadata(p->qdomain, "TSIG-ALLOW-2136", tsigKeys);
  if (tsigKeys.size() > 0) {
    bool validKey = false;
    
    TSIGRecordContent trc;
    string inputkey, message;
    if (! p->getTSIGDetails(&trc,  &inputkey, &message)) {
      L<<Logger::Error<<msgPrefix<<"TSIG key required, but packet does not contain key. Sending REFUSED"<<endl;
      return RCode::Refused;
    }

    for(vector<string>::const_iterator key=tsigKeys.begin(); key != tsigKeys.end(); key++) {
      if (inputkey == *key) // because checkForCorrectTSIG has already been performed earlier on, if the names of the ky match with the domain given. THis is valid.
        validKey=true;
    }

    if (!validKey) {
      L<<Logger::Error<<msgPrefix<<"TSIG key ("<<inputkey<<") required, but no matching key found in domainmetadata, tried "<<tsigKeys.size()<<". Sending REFUSED"<<endl;
      return RCode::Refused;
    }
  }

  if (tsigKeys.size() == 0 && p->d_havetsig)
    L<<Logger::Warning<<msgPrefix<<"TSIG is provided, but domain is not secured with TSIG. Processing continues"<<endl;

  // RFC2136 uses the same DNS Header and Message as defined in RFC1035.
  // This means we can use the MOADNSParser to parse the incoming packet. The result is that we have some different 
  // variable names during the use of our MOADNSParser.
  MOADNSParser mdp(p->getString());
  if (mdp.d_header.qdcount != 1) {
    L<<Logger::Warning<<msgPrefix<<"Zone Count is not 1, sending FormErr"<<endl;
    return RCode::FormErr;
  }     

  if (p->qtype.getCode() != QType::SOA) { // RFC2136 2.3 - ZTYPE must be SOA
    L<<Logger::Warning<<msgPrefix<<"Query ZTYPE is not SOA, sending FormErr"<<endl;
    return RCode::FormErr;
  }

  if (p->qclass != QClass::IN) {
    L<<Logger::Warning<<msgPrefix<<"Class is not IN, sending NotAuth"<<endl;
    return RCode::NotAuth;
  }

  DomainInfo di;
  di.backend=0;
  if(!B.getDomainInfo(p->qdomain, di) || !di.backend) {
    L<<Logger::Error<<msgPrefix<<"Can't determine backend for domain '"<<p->qdomain<<"' (or backend does not support RFC2136 operation)"<<endl;
    return RCode::NotAuth;
  }

  if (di.kind == DomainInfo::Slave) { //TODO: We do not support the forwarding to master stuff.. which we should ;-)
    L<<Logger::Error<<msgPrefix<<"We are slave for the domain and do not support forwarding to master, sending NotImp"<<endl;
    return RCode::NotImp;
  }

  // Check if all the records provided are within the zone 
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    // Skip this check for other field types (like the TSIG -  which is in the additional section)
    // For a TSIG, the label is the dnskey.
    if (! (rr->d_place == DNSRecord::Answer || rr->d_place == DNSRecord::Nameserver)) 
      continue;

    string label = stripDot(rr->d_label);

    if (!endsOn(label, di.zone)) {
      L<<Logger::Error<<msgPrefix<<"Received update/record out of zone, sending NotZone."<<endl;
      return RCode::NotZone;
    }
  }

  //TODO: Start a lock here, to make section 3.7 correct???
  L<<Logger::Info<<msgPrefix<<"starting transaction."<<endl;
  if (!di.backend->startTransaction(p->qdomain, -1)) { // Not giving the domain_id means that we do not delete the records.
    L<<Logger::Error<<msgPrefix<<"Backend for domain "<<p->qdomain<<" does not support transaction. Can't do Update packet."<<endl;
    return RCode::NotImp;
  }

  // 3.2.1 and 3.2.2 - Prerequisite check 
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_place == DNSRecord::Answer) {
      int res = updatePrerequisitesCheck(rr, &di);
      if (res>0) {
        L<<Logger::Error<<msgPrefix<<"Failed PreRequisites check, returning "<<res<<endl;
        di.backend->abortTransaction();
        return res;
      }
    } 
  }

  // 3.2.3 - Prerequisite check - this is outside of updatePrequisitesCheck because we check an RRSet and not the RR.
  typedef pair<string, QType> rrSetKey_t;
  typedef vector<DNSResourceRecord> rrVector_t;
  typedef std::map<rrSetKey_t, rrVector_t> RRsetMap_t;
  RRsetMap_t preReqRRsets;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_place == DNSRecord::Answer) {
      // Last line of 3.2.3
      if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY) 
        return RCode::FormErr;

      if (rr->d_class == QClass::IN) {
        rrSetKey_t key = make_pair(stripDot(rr->d_label), rr->d_type);
        rrVector_t *vec = &preReqRRsets[key];
        vec->push_back(DNSResourceRecord(*rr));
      }
    }
  }

  if (preReqRRsets.size() > 0) {
    RRsetMap_t zoneRRsets;
    for (RRsetMap_t::iterator preRRSet = preReqRRsets.begin(); preRRSet != preReqRRsets.end(); ++preRRSet) {
      rrSetKey_t rrSet=preRRSet->first;
      rrVector_t *vec = &preRRSet->second;

      DNSResourceRecord rec;
      di.backend->lookup(QType(QType::ANY), rrSet.first);
      uint16_t foundRR=0, matchRR=0;
      while (di.backend->get(rec)) {
        if (rec.qtype == rrSet.second) {
          foundRR++;
          for(rrVector_t::iterator rrItem=vec->begin(); rrItem != vec->end(); ++rrItem) {
            rrItem->ttl = rec.ttl; // The compare one line below also compares TTL, so we make them equal because TTL is not user within prerequisite checks.
            if (*rrItem == rec) 
              matchRR++;
          }
        }
      }
      if (matchRR != foundRR || foundRR != vec->size()) {
        L<<Logger::Error<<msgPrefix<<"Failed PreRequisites check, returning NXRRSet"<<endl;
        di.backend->abortTransaction();
        return RCode::NXRRSet;
      }
    }
  }



  // 3.4 - Prescan & Add/Update/Delete records
  uint16_t changedRecords = 0;
  try {

    // 3.4.1 - Prescan section
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSRecord::Nameserver) {
        int res = updatePrescanCheck(rr);
        if (res>0) {
          L<<Logger::Error<<msgPrefix<<"Failed prescan check, returning "<<res<<endl;
          di.backend->abortTransaction();
          return res;
        }
      }
    }

    bool updatedSerial=false;
    NSEC3PARAMRecordContent ns3pr;
    bool narrow; 
    bool haveNSEC3 = d_dk.getNSEC3PARAM(di.zone, &ns3pr, &narrow);

    // We get all the before/after fields before doing anything to the db.
    // We can't do this inside performUpdate() because when we remove a delegate, the before/after result is different to what it should be
    // to purge the cache correctly - One update/delete might cause a before/after to be created which is before/after the original before/after.
    vector< pair<string, string> > beforeAfterSet;
    if (!haveNSEC3) {
      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
        const DNSRecord *rr = &i->first;
        if (rr->d_place == DNSRecord::Nameserver) {
          string before, after;
          di.backend->getBeforeAndAfterNames(di.id, di.zone, stripDot(rr->d_label), before, after, (rr->d_class != QClass::IN));
          beforeAfterSet.push_back(make_pair(before, after));
        }
      }
    }

    // 3.4.2 - Perform the updates \0/
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSRecord::Nameserver) {
        changedRecords += performUpdate(msgPrefix, rr, &di, narrow, haveNSEC3, &ns3pr, &updatedSerial);
      }
    }

    // Purge the records!
    if (changedRecords > 0) {
      if (haveNSEC3) {
        string zone(di.zone);
        zone.append("$");
        PC.purge(zone);  // For NSEC3, nuke the complete zone.
      } else {
        for(vector< pair<string, string> >::const_iterator i=beforeAfterSet.begin(); i != beforeAfterSet.end(); i++)
          PC.purgeRange(i->first, i->second, di.zone);
      }
    }

    // Section 3.6 - Update the SOA serial - outside of performUpdate because we do a SOA update for the complete update message
    if (changedRecords > 0 && !updatedSerial)
      increaseSerial(msgPrefix, di);
  }
  catch (AhuException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught AhuException: "<<e.reason<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (...) {
    L<<Logger::Error<<msgPrefix<<"Caught unknown exception when performing update. Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  
  if (!di.backend->commitTransaction()) {
    L<<Logger::Error<<msgPrefix<<"Failed to commit update for domain "<<di.zone<<"!"<<endl;
    return RCode::ServFail;
  }
 
  L<<Logger::Info<<msgPrefix<<"Update completed, "<<changedRecords<<" changed records commited."<<endl;
  return RCode::NoError; //rfc 2136 3.4.2.5
}

void PacketHandler::increaseSerial(const string &msgPrefix, const DomainInfo& di) {
  DNSResourceRecord rec, newRec;
  di.backend->lookup(QType(QType::SOA), di.zone);
  bool foundSOA=false;
  while (di.backend->get(rec)) {
    newRec = rec;
    foundSOA=true;
  }
  if (!foundSOA) {
    throw AhuException("SOA-Serial update failed because there was no SOA. Wowie.");
  }
  SOAData soa2Update;
  fillSOAData(rec.content, soa2Update);

  vector<string> soaEdit2136Setting;
  B.getDomainMetadata(di.zone, "SOA-EDIT-2136", soaEdit2136Setting);
  string soaEdit2136 = "DEFAULT";
  string soaEdit;
  if (!soaEdit2136Setting.empty()) {
    soaEdit2136 = soaEdit2136Setting[0];
    if (pdns_iequals(soaEdit2136, "SOA-EDIT") || pdns_iequals(soaEdit2136,"SOA-EDIT-INCREASE") ){
      vector<string> soaEditSetting;
      B.getDomainMetadata(di.zone, "SOA-EDIT", soaEditSetting);
      if (soaEditSetting.empty()) {
        L<<Logger::Error<<msgPrefix<<"Using "<<soaEdit2136<<" for SOA-EDIT-2136 increase on RFC2136, but SOA-EDIT is not set for domain. Using DEFAULT for SOA-EDIT-2136"<<endl;
        soaEdit2136 = "DEFAULT";
      } else
        soaEdit = soaEditSetting[0];
    }
  }


  if (pdns_iequals(soaEdit2136, "INCREASE"))
    soa2Update.serial++;
  else if (pdns_iequals(soaEdit2136, "SOA-EDIT-INCREASE")) {
    uint32_t newSer = calculateEditSOA(soa2Update, soaEdit);
    if (newSer <= soa2Update.serial)
      soa2Update.serial++;
    else
      soa2Update.serial = newSer;
  } else if (pdns_iequals(soaEdit2136, "SOA-EDIT"))
    soa2Update.serial = calculateEditSOA(soa2Update, soaEdit);
  else if (pdns_iequals(soaEdit2136, "EPOCH"))
    soa2Update.serial = time(0);
  else {
    time_t now = time(0);
    struct tm tm;
    localtime_r(&now, &tm);
    boost::format fmt("%04d%02d%02d%02d");
    string newserdate=(fmt % (tm.tm_year+1900) % (tm.tm_mon +1 )% tm.tm_mday % 1).str();
    uint32_t newser = atol(newserdate.c_str());
    if (newser <= soa2Update.serial)
      soa2Update.serial++;
    else
      soa2Update.serial = newser;
  }
  

  newRec.content = serializeSOAData(soa2Update);
  di.backend->updateRecord(rec, newRec);
  PC.purge(newRec.qname); 
}


int PacketHandler::processNotify(DNSPacket *p)
{
  /* now what? 
     was this notification from an approved address?
     We determine our internal SOA id (via UeberBackend)
     We determine the SOA at our (known) master
     if master is higher -> do stuff
  */
  if(!::arg().mustDo("slave")) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" but slave support is disabled in the configuration"<<endl;
    return RCode::NotImp;
  }
  DNSBackend *db=0;
  DomainInfo di;
  di.serial = 0;
  if(!B.getDomainInfo(p->qdomain, di) || !(db=di.backend)) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" for which we are not authoritative"<<endl;
    return trySuperMaster(p);
  }
    
  if(::arg().contains("trusted-notification-proxy", p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from trusted-notification-proxy "<< p->getRemote()<<endl;
    if(di.masters.empty()) {
      L<<Logger::Error<<"However, "<<p->qdomain<<" does not have any masters defined"<<endl;
      return RCode::Refused;
    }
  }
  else if(!db->isMaster(p->qdomain, p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" which is not a master"<<endl;
    return RCode::Refused;
  }
    
  // ok, we've done our checks
  di.backend = 0;
  Communicator.addSlaveCheckRequest(di, p->d_remote);
  return 0;
}

bool validDNSName(const string &name)
{
  string::size_type pos, length=name.length();
  char c;
  for(pos=0; pos < length; ++pos) {
    c=name[pos];
    if(!((c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') ||
         c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@' || c==' ' || c=='\\'))
      return false;
  }
  return true;
}  

DNSPacket *PacketHandler::question(DNSPacket *p)
{
  DNSPacket *ret;

  if(d_pdl)
  {
    ret=d_pdl->prequery(p);
    if(ret)
      return ret;
  }

  bool shouldRecurse=false;
  ret=questionOrRecurse(p, &shouldRecurse);
  if(shouldRecurse) {
    DP->sendPacket(p);
  }
  return ret;
}

void PacketHandler::synthesiseRRSIGs(DNSPacket* p, DNSPacket* r)
{
  DLOG(L<<"Need to fake up the RRSIGs if someone asked for them explicitly"<<endl);
  typedef map<uint16_t, vector<shared_ptr<DNSRecordContent> > > records_t;
  records_t records;

  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);

  DNSResourceRecord rr;

  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer
  getAuth(p, &sd, p->qdomain, 0);

  rr.ttl=sd.default_ttl;
  B.lookup(QType(QType::ANY), p->qdomain, p);

  while(B.get(rr)) {
    if(!rr.auth) 
      continue;
    
    // this deals with the 'prio' mismatch!
    if(rr.qtype.getCode()==QType::MX || rr.qtype.getCode() == QType::SRV) {  
      rr.content = lexical_cast<string>(rr.priority) + " " + rr.content;
    }
    
    if(!rr.content.empty() && rr.qtype.getCode()==QType::TXT && rr.content[0]!='"') {
      rr.content="\""+rr.content+"\"";
    }
    if(rr.content.empty())  // empty contents confuse the MOADNS setup
      rr.content=".";
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content)); 
    
    records[rr.qtype.getCode()].push_back(drc);
    nrc.d_set.insert(rr.qtype.getCode());
  }
  bool narrow;
  NSEC3PARAMRecordContent ns3pr;
  bool doNSEC3= d_dk.getNSEC3PARAM(sd.qname, &ns3pr, &narrow);
  if(doNSEC3) {
    DLOG(L<<"We don't yet add NSEC3 to explicit RRSIG queries correctly yet! (narrow="<<narrow<<")"<<endl);
  }
  else {
    // now get the NSEC too (since we must sign it!)
    string before,after;
    sd.db->getBeforeAndAfterNames(sd.domain_id, sd.qname, p->qdomain, before, after);
  
    nrc.d_next=after;
  
    rr.qname=p->qdomain;
    // rr.ttl is already set.. we hope
    rr.qtype=QType::NSEC;
    rr.content=nrc.getZoneRepresentation();
    records[QType::NSEC].push_back(shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content)));
  
    // ok, the NSEC is in..
  }
  DLOG(L<<"Have "<<records.size()<<" rrsets to sign"<<endl);

  rr.qname = p->qdomain;
  // again, rr.ttl is already set
  rr.auth = 0; // please don't sign this!
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.qtype = QType::RRSIG;

  BOOST_FOREACH(records_t::value_type& iter, records) {
    vector<RRSIGRecordContent> rrcs;
    
    getRRSIGsForRRSET(d_dk, sd.qname, p->qdomain, iter.first, 3600, iter.second, rrcs, iter.first == QType::DNSKEY);
    BOOST_FOREACH(RRSIGRecordContent& rrc, rrcs) {
      rr.content=rrc.getZoneRepresentation();
      r->addRecord(rr);
    }
  }
}

void PacketHandler::makeNXDomain(DNSPacket* p, DNSPacket* r, const std::string& target, const std::string& nextcloser, SOAData& sd)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=min(sd.ttl, sd.default_ttl);
  rr.signttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  rr.scopeMask = sd.scopeMask;
  r->addRecord(rr);
  
  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, nextcloser, sd.qname, 4);
  
  r->setRcode(RCode::NXDomain);  
  S.ringAccount("nxdomain-queries",p->qdomain+"/"+p->qtype.getName());
}

void PacketHandler::makeNOError(DNSPacket* p, DNSPacket* r, const std::string& target, SOAData& sd, int mode)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=sd.ttl;
  rr.ttl=min(sd.ttl, sd.default_ttl);
  rr.signttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  r->addRecord(rr);

  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, target, sd.qname, mode);

  S.ringAccount("noerror-queries",p->qdomain+"/"+p->qtype.getName());
}


bool PacketHandler::addDSforNS(DNSPacket* p, DNSPacket* r, SOAData& sd, const string& dsname)
{
  //cerr<<"Trying to find a DS for '"<<dsname<<"', domain_id = "<<sd.domain_id<<endl;
  B.lookup(QType(QType::DS), dsname, p, sd.domain_id);
  DNSResourceRecord rr;
  bool gotOne=false;
  while(B.get(rr)) {
    gotOne=true;
    rr.d_place = DNSResourceRecord::AUTHORITY;
    rr.auth=true; // please sign it!
    r->addRecord(rr);
  }
  return gotOne;
}

bool PacketHandler::tryReferral(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  vector<DNSResourceRecord> rrset = getBestReferralNS(p, sd, target);
  if(rrset.empty())
    return false;
  
  DLOG(L<<"The best NS is: "<<rrset.begin()->qname<<endl);
  BOOST_FOREACH(DNSResourceRecord rr, rrset) {
    DLOG(L<<"\tadding '"<<rr.content<<"'"<<endl);
    rr.d_place=DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  r->setA(false);

  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname) && !addDSforNS(p, r, sd, rrset.begin()->qname))
    addNSECX(p, r, rrset.begin()->qname, rrset.begin()->qname, sd.qname, 1);
  
  return true;
}

void PacketHandler::completeANYRecords(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  if(!p->d_dnssecOk)
    ; // cerr<<"Need to add all the RRSIGs too for '"<<target<<"', should do this manually since DNSSEC was not requested"<<endl;
  //  cerr<<"Need to add all the NSEC too.."<<endl; /// XXX FIXME THE ABOVE IF IS WEIRD
  
  if(!d_dk.isSecuredZone(sd.qname))
    return;
    
  addNSECX(p, r, target, target, sd.qname, 5); 
  if(pdns_iequals(sd.qname, p->qdomain)) {
    addDNSKEY(p, r, sd);
    addNSEC3PARAM(p, r, sd);
  }
}

bool PacketHandler::tryWildcard(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target, string &wildcard, bool& retargeted, bool& nodata)
{
  retargeted = nodata = false;

  vector<DNSResourceRecord> rrset;
  if(!getBestWildcard(p, sd, target, wildcard, &rrset))
    return false;

  if(rrset.empty()) {
    DLOG(L<<"Wildcard matched something, but not of the correct type"<<endl);
    nodata=true;
  }
  else {
    DLOG(L<<"The best wildcard match: "<<rrset.begin()->qname<<endl);
    BOOST_FOREACH(DNSResourceRecord rr, rrset) {
      rr.wildcardname = rr.qname;
      rr.qname=target;

      if(rr.qtype.getCode() == QType::CNAME)  {
        retargeted=true;
        target=rr.content;
      }
  
      DLOG(L<<"\tadding '"<<rr.content<<"'"<<endl);
      rr.d_place=DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
  }
  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname) && !nodata) {
    addNSECX(p, r, p->qdomain, wildcard, sd.qname, 3);
  }
  return true;
}

//! Called by the Distributor to ask a question. Returns 0 in case of an error
DNSPacket *PacketHandler::questionOrRecurse(DNSPacket *p, bool *shouldRecurse)
{
  *shouldRecurse=false;
  DNSResourceRecord rr;
  SOAData sd;
  sd.db=0;
  
  string subdomain="";
  string soa;
  int retargetcount=0;
  set<string, CIStringCompare> authSet;

  vector<DNSResourceRecord> rrset;
  bool weDone=0, weRedirected=0, weHaveUnauth=0;

  DNSPacket *r=0;
  bool noCache=false;
  
  if(p->d.qr) { // QR bit from dns packet (thanks RA from N)
    L<<Logger::Error<<"Received an answer (non-query) packet from "<<p->getRemote()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    return 0;
  }

  if(p->d_havetsig) {
    string keyname, secret;
    TSIGRecordContent trc;
    if(!checkForCorrectTSIG(p, &B, &keyname, &secret, &trc)) {
      r=p->replyPacket();  // generate an empty reply packet
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a TSIG signed message with a non-validating key"<<endl;

      // RFC3007 describes that a non-secure message should be sending Refused for DNS Updates
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused); 
      else 
        r->setRcode(RCode::NotAuth);
      return r;
    }
    p->setTSIGDetails(trc, keyname, secret, trc.d_mac); // this will get copied by replyPacket()
    noCache=true;
  }
  
  r=p->replyPacket();  // generate an empty reply packet, possibly with TSIG details inside
  
  try {    

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p->qdomain)) {
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a malformed qdomain from "<<p->getRemote()<<", '"<<p->qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      r->setRcode(RCode::ServFail);
      return r;
    }
    if(p->d.opcode) { // non-zero opcode (again thanks RA!)
      if(p->d.opcode==Opcode::Update) {
        S.inc("rfc2136-queries");
        int res=processUpdate(p);
        if (res == RCode::Refused)
          S.inc("rfc2136-refused");
        else if (res != RCode::ServFail)
          S.inc("rfc2136-answers");
        r->setRcode(res);
        r->setOpcode(Opcode::Update);
        return r;
      }
      else if(p->d.opcode==Opcode::Notify) {
        int res=processNotify(p);
        if(res>=0) {
          r->setRcode(res);
          r->setOpcode(Opcode::Notify);
          return r;
        }
        delete r;
        return 0;
      }
      
      L<<Logger::Error<<"Received an unknown opcode "<<p->d.opcode<<" from "<<p->getRemote()<<" for "<<p->qdomain<<endl;

      r->setRcode(RCode::NotImp); 
      return r; 
    }

    // L<<Logger::Warning<<"Query for '"<<p->qdomain<<"' "<<p->qtype.getName()<<" from "<<p->getRemote()<<endl;
    
    r->d.ra = (p->d.rd && d_doRecursion && DP->recurseFor(p));  // make sure we set ra if rd was set, and we'll do it

    if(p->qtype.getCode()==QType::IXFR) {
      r->setRcode(RCode::NotImp);
      return r;
    }

    // please don't query fancy records directly!
    if(d_doFancyRecords && (p->qtype.getCode()==QType::URL || p->qtype.getCode()==QType::CURL || p->qtype.getCode()==QType::MBOXFW)) {
      r->setRcode(RCode::ServFail);
      return r;
    }
    
    string target=p->qdomain;
    
    if(doVersionRequest(p,r,target)) // catch version.bind requests
      goto sendit;

    if(p->qclass==255) // any class query 
      r->setA(false);
    else if(p->qclass != QClass::IN) // we only know about IN, so we don't find anything
      goto sendit;

  retargeted:;
    if(retargetcount > 10) {    // XXX FIXME, retargetcount++?
      r->setRcode(RCode::ServFail);
      return r;
    }
    
    if(!getAuth(p, &sd, target, 0)) {
      DLOG(L<<Logger::Error<<"We have no authority over zone '"<<target<<"'"<<endl);
      if(r->d.ra) {
        DLOG(L<<Logger::Error<<"Recursion is available for this remote, doing that"<<endl);
        *shouldRecurse=true;
        delete r;
        return 0;
      }
      
      if(!retargetcount)
        r->setA(false); // drop AA if we never had a SOA in the first place
      if(::arg().mustDo("send-root-referral")) {
        DLOG(L<<Logger::Warning<<"Adding root-referral"<<endl);
        addRootReferral(r);
      }
      else {
        DLOG(L<<Logger::Warning<<"setting 'No Error'"<<endl);
      }
      goto sendit;
    }
    DLOG(L<<Logger::Error<<"We have authority, zone='"<<sd.qname<<"', id="<<sd.domain_id<<endl);
    authSet.insert(sd.qname); 

    if(pdns_iequals(sd.qname, p->qdomain)) {
      if(p->qtype.getCode() == QType::DNSKEY)
      {
        if(addDNSKEY(p, r, sd))
          goto sendit;
      }
      else if(p->qtype.getCode() == QType::NSEC3PARAM)
      {
        if(addNSEC3PARAM(p,r, sd))
          goto sendit;
      }
    }

    if(p->qtype.getCode() == QType::SOA && pdns_iequals(sd.qname, p->qdomain)) {
     	rr.qname=sd.qname;
      rr.qtype=QType::SOA;
      rr.content=serializeSOAData(sd);
      rr.ttl=sd.ttl;
      rr.domain_id=sd.domain_id;
      rr.d_place=DNSResourceRecord::ANSWER;
      rr.auth = true;
      r->addRecord(rr);
      goto sendit;
    }

    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::NSEC && p->d_dnssecOk && d_dk.isSecuredZone(sd.qname) && !d_dk.getNSEC3PARAM(sd.qname, 0)) {
      addNSEC(p, r, target, sd.qname, 5); // only NSEC please
      goto sendit;
    }

    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::RRSIG && d_dk.isSecuredZone(sd.qname)) {
      synthesiseRRSIGs(p, r);
      goto sendit;  
    }

    DLOG(L<<"Checking for referrals first, unless this is a DS query"<<endl);
    if(p->qtype.getCode() != QType::DS && tryReferral(p, r, sd, target))
      goto sendit;

    DLOG(L<<"Got no referrals, trying ANY"<<endl);

    // see what we get..
    B.lookup(QType(QType::ANY), target, p, sd.domain_id);
    rrset.clear();
    weDone = weRedirected = weHaveUnauth = 0;
    
    while(B.get(rr)) {
      if (p->qtype.getCode() == QType::ANY && rr.qtype.getCode() == QType::RRSIG) // RRSIGS are added later any way.
        continue; //TODO: this actually means addRRSig should check if the RRSig is already there.

      if(rr.qtype.getCode() == QType::DS)
        rr.auth = 1;
      // cerr<<"Auth: "<<rr.auth<<", "<<(rr.qtype == p->qtype)<<", "<<rr.qtype.getName()<<endl;
      if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.auth) 
        weDone=1;
      // the line below fakes 'unauth NS' for delegations for non-DNSSEC backends.
      if((rr.qtype == p->qtype && !rr.auth) || (rr.qtype.getCode() == QType::NS && (!rr.auth || !pdns_iequals(sd.qname, rr.qname))))
        weHaveUnauth=1;

      if(rr.qtype.getCode() == QType::CNAME && p->qtype.getCode() != QType::CNAME) 
        weRedirected=1;
        
      if(rr.qtype.getCode() == QType::SOA && pdns_iequals(rr.qname, sd.qname)) { // fix up possible SOA adjustments for this zone
        rr.content=serializeSOAData(sd);
        rr.ttl=sd.ttl;
        rr.domain_id=sd.domain_id;
        rr.auth = true;
      }
      
      rrset.push_back(rr);
    }

    DLOG(L<<"After first ANY query for '"<<target<<"', id="<<sd.domain_id<<": weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<endl);
    if(p->qtype.getCode() == QType::DS && weHaveUnauth &&  !weDone && !weRedirected && d_dk.isSecuredZone(sd.qname)) {
      DLOG(L<<"Q for DS of a name for which we do have NS, but for which we don't have on a zone with DNSSEC need to provide an AUTH answer that proves we don't"<<endl);
      makeNOError(p, r, target, sd, 1);
      goto sendit;
    }

    if(rrset.empty()) {
      DLOG(L<<"checking qtype.getCode() ["<<(p->qtype.getCode())<<"] against QType::DS ["<<(QType::DS)<<"]"<<endl);
      if(p->qtype.getCode() == QType::DS)
      {
        DLOG(L<<"DS query found no direct result, trying referral now"<<endl);
        if(tryReferral(p, r, sd, target))
        {
          DLOG(L<<"got referral for DS query"<<endl);
          goto sendit;
        }
      }

      DLOG(L<<Logger::Warning<<"Found nothing in the by-name ANY, but let's try wildcards.."<<endl);
      bool wereRetargeted(false), nodata(false);
      string wildcard;
      if(tryWildcard(p, r, sd, target, wildcard, wereRetargeted, nodata)) {
        if(wereRetargeted) {
          retargetcount++;
          goto retargeted;
        }
        if(nodata) {
          target=wildcard;
          makeNOError(p, r, target, sd, 2);
        }
        goto sendit;
      }
      else
      {        
        makeNXDomain(p, r, target, wildcard, sd);
      }
      
      goto sendit;
    }
        			       
    if(weRedirected) {
      BOOST_FOREACH(rr, rrset) {
        if(rr.qtype.getCode() == QType::CNAME) {
          r->addRecord(rr);
          target = rr.content;
          retargetcount++;
          goto retargeted;
        }
      }
    }
    else if(weDone) {
      bool haveRecords = false;
      BOOST_FOREACH(rr, rrset) {
        if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.qtype.getCode() && rr.auth) {
          r->addRecord(rr);
          haveRecords = true;
        }
      }

      if (haveRecords) {
        if(p->qtype.getCode() == QType::ANY)
          completeANYRecords(p, r, sd, target);
      }
      else
        makeNOError(p, r, rr.qname, sd, 0);

      goto sendit;
    }
    else if(weHaveUnauth) {
      DLOG(L<<"Have unauth data, so need to hunt for best NS records"<<endl);
      if(tryReferral(p, r, sd, target))
        goto sendit;
      L<<Logger::Error<<"Should not get here ("<<p->qdomain<<"|"<<p->qtype.getCode()<<"): please run pdnssec rectify-zone "<<sd.qname<<endl;
    }
    else {
      DLOG(L<<"Have some data, but not the right data"<<endl);
      makeNOError(p, r, target, sd, 0);
    }
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p, r, sd)<0) {
      delete r;
      return 0;
    }

    editSOA(d_dk, sd.qname, r);
    
    if(p->d_dnssecOk)
      addRRSigs(d_dk, B, authSet, r->getRRS());
      
    r->wrapup(); // needed for inserting in cache
    if(!noCache)
      PC.insert(p, r, r->getMinTTL()); // in the packet cache
  }
  catch(DBException &e) {
    L<<Logger::Error<<"Database module reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  catch(AhuException &e) {
    L<<Logger::Error<<"Database module reported permanent error which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    throw; // we WANT to die at this point
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Exception building answer packet ("<<e.what()<<") sending out servfail"<<endl;
    delete r;
    r=p->replyPacket();  // generate an empty reply packet    
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  return r; 

}

