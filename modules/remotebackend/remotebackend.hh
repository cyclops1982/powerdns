#ifndef REMOTEBACKEND_REMOTEBACKEND_HH

#include <string>
#include "pdns/namespaces.hh"
#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <boost/lexical_cast.hpp>
#include <jsoncpp/json/json.h>
#include "../pipebackend/coprocess.hh"
#include <curl/curl.h>

class Connector {
   public:
    virtual ~Connector() {};
    bool send(Json::Value &value);
    bool recv(Json::Value &value);
    virtual int send_message(const Json::Value &input) = 0;
    virtual int recv_message(Json::Value &output) = 0;
};

// fwd declarations
class UnixsocketConnector: public Connector {
  public:
    UnixsocketConnector(std::map<std::string,std::string> options);
    virtual ~UnixsocketConnector();
    virtual int send_message(const Json::Value &input);
    virtual int recv_message(Json::Value &output);
  private:
    ssize_t read(std::string &data);
    ssize_t write(const std::string &data);
    void reconnect();
    std::map<std::string,std::string> options;
    int fd;
    std::string path;
    bool connected;
};

class HTTPConnector: public Connector {
  public:

  HTTPConnector(std::map<std::string,std::string> options);
  ~HTTPConnector();

  virtual int send_message(const Json::Value &input);
  virtual int recv_message(Json::Value &output);
  friend size_t ::httpconnector_write_data(void*, size_t, size_t, void*);

  private:
    std::string d_url;
    std::string d_url_suffix;
    CURL *d_c;
    std::string d_data;
    void json2string(const Json::Value &input, std::string &output);
    void requestbuilder(const std::string &method, const Json::Value &parameters, struct curl_slist **slist);
};

class PipeConnector: public Connector {
  public:

  PipeConnector(std::map<std::string,std::string> options);
  ~PipeConnector();

  virtual int send_message(const Json::Value &input);
  virtual int recv_message(Json::Value &output);

  private:

  void launch();
  CoProcess *coproc;
  std::string command;
  std::map<std::string,std::string> options;
};

class RemoteBackend : public DNSBackend
{
  public:
  RemoteBackend(const std::string &suffix="");
  ~RemoteBackend();

  void lookup(const QType &qtype, const std::string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  bool get(DNSResourceRecord &rr);
  bool list(const std::string &target, int domain_id);

  virtual bool getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys);
  virtual bool getTSIGKey(const std::string& name, std::string* algorithm, std::string* content);
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  virtual bool getBeforeAndAfterNames(uint32_t id, const std::string& zonename, const std::string& qname, std::string& before, std::string& after);
  virtual bool setDomainMetadata(const string& name, const string& kind, const std::vector<std::basic_string<char> >& meta);
  virtual bool removeDomainKey(const string& name, unsigned int id);
  virtual int addDomainKey(const string& name, const KeyData& key);
  virtual bool activateDomainKey(const string& name, unsigned int id);
  virtual bool deactivateDomainKey(const string& name, unsigned int id);
  virtual bool getDomainInfo(const string&, DomainInfo&);
  virtual bool doesDNSSEC();

  static DNSBackend *maker();

  private:
    int build(const std::string &connstr);
    Connector *connector;
    bool d_dnssec;
    Json::Value d_result;
    int d_index; 
};
#endif
