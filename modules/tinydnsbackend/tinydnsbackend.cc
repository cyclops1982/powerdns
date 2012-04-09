#include "tinydnsbackend.hh"
#include "pdns/lock.hh"
#include <cdb.h>
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsrecords.hh>
#include <utility>
#include <boost/foreach.hpp>


static string backendname="[TinyDNSBackend] ";
uint32_t TinyDNSBackend::s_lastId;

pthread_mutex_t TinyDNSBackend::s_domainInfoLock=PTHREAD_MUTEX_INITIALIZER;
TinyDNSBackend::TDI_suffix_t TinyDNSBackend::s_domainInfo;


TinyDNSBackend::TinyDNSBackend(const string &suffix)
{
	setArgPrefix("tinydns"+suffix);
	d_suffix = suffix;
	d_locations = mustDo("locations");
	d_taiepoch = 4611686018427387904ULL + getArgAsNum("tai-adjust");

	Lock l(&s_domainInfoLock);
	TDI_t *domains; // Setup the s_domainInfo object so we can always be sure it exists for this suffix.
	if (! s_domainInfo.count(d_suffix)) {
		domains = new TDI_t;
		s_domainInfo[d_suffix] = *domains;
	}	

	if (!getArg("dnssec-db").empty()) {
		setupDNSSEC();

		domains = &s_domainInfo[d_suffix];
		if(domains->size() == 0) { // We need a list of zone's to fix the Auth field in the get()
			d_isAxfr=true;
			d_dnspacket = NULL;
			d_cdbReader=new CDB(getArg("dbfile"));
			d_cdbReader->searchAll();

			DNSResourceRecord rr;
			while (get(rr)) {
				if (rr.qtype.getCode() == QType::SOA) {
					s_lastId++;

					SOAData sd;
					fillSOAData(rr.content, sd);

					TinyDomainInfo tmp;
					tmp.zone = rr.qname;
					tmp.id = s_lastId;
					if (mustDo("notify-on-startup")) {
						tmp.notified_serial = 0;
					} else {
						tmp.notified_serial = sd.serial;
					}
					domains->insert(tmp);
				}
			}
		}
	}

}

void TinyDNSBackend::getUpdatedMasters(vector<DomainInfo>* retDomains) {
	Lock l(&s_domainInfoLock); //TODO: We could actually lock less if we do it per suffix.
	TDI_t *domains = &s_domainInfo[d_suffix];

	vector<DomainInfo> allDomains;
	getAllDomains(&allDomains);

	if (domains->size() == 0 && !mustDo("notify-on-startup")) {
		for (vector<DomainInfo>::iterator di=allDomains.begin(); di!=allDomains.end(); ++di) {
			di->notified_serial = 0;
		}
	}

	for(vector<DomainInfo>::iterator di=allDomains.begin(); di!=allDomains.end(); ++di) {
		TDIByZone_t& zone_index = domains->get<tag_zone>();
		TDIByZone_t::iterator itByZone = zone_index.find(di->zone);
		if (itByZone == zone_index.end()) { // We didn't find the zone, so it must be new!
			s_lastId++;
			di->id = s_lastId;

			TinyDomainInfo tmp;
			tmp.zone = di->zone;
			tmp.id = di->id;
			tmp.notified_serial = di->serial;
			domains->insert(tmp);

			if (di->notified_serial > 0) { 
				retDomains->push_back(*di);
			}
		} else {
			if (itByZone->notified_serial < di->serial) {
				di->id = itByZone->id;
				retDomains->push_back(*di);
			}
		}
	}
}

void TinyDNSBackend::setNotified(uint32_t id, uint32_t serial) {
	Lock l(&s_domainInfoLock);
	if (!s_domainInfo.count(d_suffix)) {
		throw new AhuException("Can't get list of domains to set the serial.");
	}
	TDI_t *domains = &s_domainInfo[d_suffix];
	TDIById_t& domain_index = domains->get<tag_domainid>();
	TDIById_t::iterator itById = domain_index.find(id);
	if (itById == domain_index.end()) {
		L<<Logger::Error<<backendname<<"Received updated serial("<<serial<<"), but domain ID ("<<id<<") is not known in this backend."<<endl;
	} else {
		DLOG(L<<Logger::Debug<<backendname<<"Setting serial for "<<itById->zone<<" to "<<serial<<endl);
		domain_index.modify(itById, TDI_SerialModifier(serial));
	}
	s_domainInfo[d_suffix] = *domains;
}

void TinyDNSBackend::getAllDomains(vector<DomainInfo> *domains) {
	d_isAxfr=true;
	d_dnspacket = NULL;

	d_cdbReader=new CDB(getArg("dbfile"));
	d_cdbReader->searchAll();
	DNSResourceRecord rr;

	while (get(rr)) {
		if (rr.qtype.getCode() == QType::SOA) {
			SOAData sd;
			fillSOAData(rr.content, sd);

			DomainInfo di;
			di.id = -1; //TODO: Check if this is ok. 
			di.backend=this;
			di.zone = rr.qname;
			di.serial = sd.serial;
			di.notified_serial = sd.serial;
			di.kind = DomainInfo::Master;
			di.last_check = time(0);
			domains->push_back(di);
		}
	}
}

bool TinyDNSBackend::list(const string &target, int domain_id) {
	d_isAxfr=true;
	DNSLabel l(target.c_str());
	string key = l.binary();
	d_cdbReader=new CDB(getArg("dbfile"));
	return d_cdbReader->searchSuffix(key);
}

void TinyDNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId) {
	d_isAxfr = false;
	string queryDomain = toLowerCanonic(qdomain);

	DNSLabel l(queryDomain.c_str());
	string key=l.binary();

	DLOG(L<<Logger::Debug<<backendname<<"[lookup] query for qtype ["<<qtype.getName()<<"] qdomain ["<<qdomain<<"]"<<endl);
//	DLOG(L<<Logger::Debug<<"[lookup] key ["<<makeHexDump(key)<<"]"<<endl);

	d_isWildcardQuery = false;
	if (key[0] == '\001' && key[1] == '\052') {
		d_isWildcardQuery = true;
		key.erase(0,2);
	}

	d_qtype=qtype;

	d_cdbReader=new CDB(getArg("dbfile"));
	d_cdbReader->searchKey(key);
	d_dnspacket = pkt_p;
}


bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	pair<string, string> record;

	while (d_cdbReader->readNext(record)) {
		string val = record.second; 
		string key = record.first;

		//DLOG(L<<Logger::Debug<<"[GET] Key: "<<makeHexDump(key)<<endl);
		//DLOG(L<<Logger::Debug<<"[GET] Val: "<<makeHexDump(val)<<endl);
		if (key[0] == '\000' && key[1] == '\045') { // skip locations
			continue;
		}

		if (!d_isAxfr) {
			// If we have a wildcard query, but the record we got is not a wildcard, we skip.
			if (d_isWildcardQuery && val[2] != '\052' && val[2] != '\053') {
				continue;
			}

			// If it is NOT a wildcard query, but we do find a wildcard record, we skip it.	
			if (!d_isWildcardQuery && (val[2] == '\052' || val[2] == '\053')) {
				continue;
			}
		}
		

		vector<uint8_t> bytes;
		const char *sval = val.c_str();
		unsigned int len = val.size();
		bytes.resize(len);
		copy(sval, sval+len, bytes.begin());
		PacketReader pr(bytes);
		rr.qtype = QType(pr.get16BitInt());

		char locwild = pr.get8BitInt();
		if(locwild != '\075' && (locwild == '\076' || locwild == '\053')) {
			if (d_isAxfr && d_locations) { // We skip records with a location in AXFR, unless we disable locations.
				continue;
			}
			char recloc[2];
			recloc[0] = pr.get8BitInt();
			recloc[1] = pr.get8BitInt();
			
			if (d_locations) {
				bool foundLocation = false;
				vector<string> locations = getLocations();
				while(locations.size() > 0) {
					string locId = locations.back();
					locations.pop_back();
	
					if (recloc[0] == locId[0] && recloc[1] == locId[1]) {
						foundLocation = true;
						break;
					}
				}
				if (!foundLocation) {
					continue;
				} 
			}
		}

		if(d_isAxfr || d_qtype.getCode() == QType::ANY || rr.qtype == d_qtype) {
			
			if (d_isAxfr && (val[2] == '\052' || val[2] == '\053' )) { // Keys are not stored with wildcard character, with AXFR we need to add that.
				key.insert(0, 1, '\052');
				key.insert(0, 1, '\001');
			}
			DNSLabel dnsKey(key.c_str(), key.size());
			rr.qname = dnsKey.human();
			rr.qname = rr.qname.erase(rr.qname.size()-1, 1);// strip the last dot, packethandler needs this.
			rr.domain_id=-1;

			//TODO: DS record?
			rr.auth = true;
			if(d_dnssecdb && rr.qtype.getCode() == QType::NS) {
				TDI_t *domains = &s_domainInfo[d_suffix];
				TDIByZone_t& zone_index = domains->get<tag_zone>();

				TDIByZone_t::iterator itByZone = zone_index.find(rr.qname);
				if (itByZone == zone_index.end()) {
					cerr<<"SETING AUTH FLAG TO FALSE"<<endl;
					rr.auth = false;
				}
			}


			rr.ttl = pr.get32BitInt();
			uint64_t timestamp = pr.get32BitInt();
			timestamp <<= 32;
			timestamp += pr.get32BitInt();
			if(timestamp) {
				uint64_t now = d_taiepoch + time(NULL);
				if (rr.ttl == 0) {
					if (timestamp < now) {
						continue;
					}
					rr.ttl = timestamp - now; 
				} else if (now <= timestamp) {
					continue;
				}
			}
	
			DNSRecord dr;
			dr.d_class = 1;
			dr.d_type = rr.qtype.getCode();
			dr.d_clen = val.size()-pr.d_pos;
			DNSRecordContent *drc = DNSRecordContent::mastermake(dr, pr);

			string content = drc->getZoneRepresentation();
			delete drc;
			if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) {
				vector<string>parts;
				stringtok(parts,content," ");
				rr.priority=atoi(parts[0].c_str());
				rr.content=content.substr(parts[0].size()+1);
			} else {
				rr.content = content;
			}
			if (!d_isAxfr) {
				DLOG(L<<Logger::Debug<<backendname<<"Returning ["<<rr.content<<"] for ["<<rr.qname<<"] of RecordType ["<<rr.qtype.getName()<<"]"<<endl;);
			}
			return true;
		}
	} // end of while
	DLOG(L<<Logger::Debug<<backendname<<"No more records to return."<<endl);
	
	delete d_cdbReader;
	return false;
}


vector<string> TinyDNSBackend::getLocations()
{
	vector<string> ret;

	if (! d_dnspacket) {
		return ret;
	}

	//TODO: We do not have IPv6 support.
	Netmask remote = d_dnspacket->getRealRemote();
	if (remote.getBits() != 32) {
		return ret;
	}
	
	unsigned long addr = remote.getNetwork().sin4.sin_addr.s_addr;	

	char key[6];
	key[0] = '\000';
	key[1] = '\045';
	key[2] = (addr      )&0xff;
	key[3] = (addr >>  8)&0xff;
	key[4] = (addr >> 16)&0xff;
	key[5] = (addr >> 24)&0xff;

	for (int i=4;i>=0;i--) {
		string searchkey(key, i+2);
		CDB *reader = new CDB(getArg("dbfile"));
		ret = reader->findall(searchkey);
		delete reader;

		//Biggest item wins, so when we find something, we can jump out.
		if (ret.size() > 0) {
			break;
		}
	}

	return ret; 
}




// boilerplate
class TinyDNSFactory: public BackendFactory
{
public:
	TinyDNSFactory() : BackendFactory("tinydns") {}

	void declareArguments(const string &suffix="") {
		declare(suffix, "notify-on-startup", "Tell the TinyDNSBackend to notify all the slave nameservers on startup. Default is no.", "no");
		declare(suffix, "dbfile", "Location of the cdb data file", "data.cdb");
		declare(suffix, "tai-adjust", "This adjusts the TAI value if timestamps are used. These seconds will be added to the start point (1970) and will allow you to adjust for leap seconds. The default is 10.", "10");
		declare(suffix, "locations", "Enable or Disable location support in the backend. Changing the value to 'no' will make the backend ignore the locations. This then returns all records!", "yes");
		declare(suffix, "dnssec-db", "Filename to store & access our DNSSEC metadatabase, empty for none", "");
	}


	DNSBackend *make(const string &suffix="") {
		return new TinyDNSBackend(suffix);
	}
};

// boilerplate
class TinyDNSLoader
{
public:
	TinyDNSLoader() {
		BackendMakers().report(new TinyDNSFactory);
		L<<Logger::Info<<" [TinyDNSBackend] This is the TinyDNSBackend ("__DATE__", "__TIME__") reporting"<<endl;
	}
};

static TinyDNSLoader tinydnsloader;
