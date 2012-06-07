$TTL 3600
$ORIGIN test.com.
@		IN	SOA	ns1.test.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	MX	10	smtp-servers.example.com.
@			IN	MX	15	smtp-servers
www			IN	CNAME	server1
server1			IN	A	1.2.3.4
ns1			IN	A	10.0.1.1
ns2			IN	A	10.0.1.2
