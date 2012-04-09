#include "tinydnsbackend.hh"
#include "pdns/lock.hh"
#include <pdns/misc.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsrecords.hh>
#include <utility>
#include <boost/foreach.hpp>
#include "bind-dnssec.schema.sqlite3.sql.h"
#include "config.h"


#ifndef HAVE_SQLITE3
void TinyDNSBackend::setupDNSSEC()
{
  throw runtime_error("tinydns-dnssec-db requires building PowerDNS with SQLite3");
}

void TinyDNSBackend::createDNSSECDB(const string& fname)
{}

bool TinyDNSBackend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{ return false; }

bool TinyDNSBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{ return false; }

bool TinyDNSBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{ return false; }

bool TinyDNSBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{ return false; }

bool TinyDNSBackend::removeDomainKey(const string& name, unsigned int id)
{ return false; }

int TinyDNSBackend::addDomainKey(const string& name, const KeyData& key)
{ return false; }

bool TinyDNSBackend::activateDomainKey(const string& name, unsigned int id)
{ return false; }

bool TinyDNSBackend::deactivateDomainKey(const string& name, unsigned int id)
{ return false; }

bool TinyDNSBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{ return false; }

bool TinyDNSBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{ return false; }
#else



#include "pdns/ssqlite3.hh"
bool TinyDNSBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{ 
  throw runtime_error("The TinyDNSBackend can only be operated in NSEC3-narrow mode. The current configuration is not NSEC3-narrow.");
} 


void TinyDNSBackend::setupDNSSEC()
{
  if(getArg("dnssec-db").empty())
    return;
  try {

    d_dnssecdb = shared_ptr<SSQLite3>(new SSQLite3(getArg("dnssec-db")));
  }
  catch(SSqlException& se) {
    // this error is meant to kill the server dead - it makes no sense to continue..
    throw runtime_error("Error opening DNSSEC database in TinyDNS backend: "+se.txtReason());
  }
}


bool TinyDNSBackend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{
  string value;
  vector<string> meta;
  getDomainMetadata(zname, "NSEC3PARAM", meta);
  if(!meta.empty())
    value=*meta.begin();
  
  if(value.empty()) { // "no NSEC3"
    return false;
  }
     
  if(ns3p) {
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, value));
    *ns3p = *tmp;
    delete tmp;
  }
  return true;
}

bool TinyDNSBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecdb)
    return false;
 
  boost::format fmt("select content from domainmetadata where domain='%s' and kind='%s'");
  try {
    d_dnssecdb->doQuery((fmt % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind)).str());
  
    vector<string> row;
    while(d_dnssecdb->getRow(row)) {
      meta.push_back(row[0]);
    }
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());
  }
  return true;
}

bool TinyDNSBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecdb)
    return false;
  
  boost::format fmt("delete from domainmetadata where domain='%s' and kind='%s'");
  boost::format fmt2("insert into domainmetadata (domain, kind, content) values ('%s','%s', '%s')");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind)).str());
    if(!meta.empty())
      d_dnssecdb->doCommand((fmt2 % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind) % d_dnssecdb->escape(meta.begin()->c_str())).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());
  }
  return true;

}

bool TinyDNSBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  // cerr<<"Asked to get keys for zone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
  boost::format fmt("select id,flags, active, content from cryptokeys where domain='%s'");
  try {
    d_dnssecdb->doQuery((fmt % d_dnssecdb->escape(name)).str());
    KeyData kd;
    vector<string> row;
    while(d_dnssecdb->getRow(row)) {
      kd.id = atoi(row[0].c_str());
      kd.flags = atoi(row[1].c_str());
      kd.active = atoi(row[2].c_str());
      kd.content = row[3];
      keys.push_back(kd);
    }
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());
  }
  
  return true;
}

bool TinyDNSBackend::removeDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecdb)
    return false;
  
  cerr<<"Asked to remove key "<<id<<" in zone '"<<name<<"'\n";
  
  boost::format fmt("delete from cryptokeys where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    cerr<<se.txtReason()  <<endl;
  }
  
  return true;
}

int TinyDNSBackend::addDomainKey(const string& name, const KeyData& key)
{
  if(!d_dnssecdb)
    return false;
  
  //cerr<<"Asked to add a key to zone '"<<name<<"'\n";
  
  boost::format fmt("insert into cryptokeys (domain, flags, active, content) values ('%s', %d, %d, '%s')");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % key.flags % key.active % d_dnssecdb->escape(key.content)).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());    
  }
  
  return true;
}

bool TinyDNSBackend::activateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to activate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
  
  boost::format fmt("update cryptokeys set active=1 where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());    
  }
  
  return true;
}

bool TinyDNSBackend::deactivateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to deactivate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
    
  boost::format fmt("update cryptokeys set active=0 where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in TinyDNS backend: "+se.txtReason());
  }
  
  return true;
}

bool TinyDNSBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  if(!d_dnssecdb)
    return false;
  boost::format fmt("select algorithm, secret from tsigkeys where name='%s'");
  
  try {
    d_dnssecdb->doQuery( (fmt % d_dnssecdb->escape(name)).str());
  }
  catch (SSqlException &e) {
    throw AhuException("TinyDNSBackend unable to retrieve named TSIG key: "+e.txtReason());
  }
  
  SSql::row_t row;
  
  content->clear();
  while(d_dnssecdb->getRow(row)) {
    *algorithm = row[0];
    *content=row[1];
  }

  return !content->empty();

}


#endif
