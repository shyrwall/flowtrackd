Basic Perl implementation of TCP Reset Cookies for Unidirectional Anti-DDOS. Used for example for Cloudflares Magic Transit.

Example,

ipset create shield_whitelist_eth0 hash:ip,port,ip family inet maxelem 65535 timeout 3600

iptables -t raw -A PREROUTING -p tcp --dport 80 -m set --match-set shield_whitelist_eth0 src,dst,dst -j ACCEPT

iptables -t raw -A PREROUTING -p tcp --dport 80 -j DROP

./flowtrackd.pl eth0
