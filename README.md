# topip2geo
Gather person IP address while using skype or other p2p video chat by analyzing traffic

# Dependencies (perm modules):
* Net::Pcap
* NetPacket
* Geo::IP::PurePerl

# Installation:
`sudo apt install libnet-pcap-perl libnetpacket-perl libgeo-ip-perl cpan
`sudo cpan install Geo::IP::PurePerl`

# Usage:
we need privileges to capture packets on interface wlan0:
`sudo perl topip2geo.pl wlp3s0`

# Example output:
```$ sudo perl topip2geo.pl wlp3s0
wlp3s0 mac = f4:5c:89:b4:17:6f
Listen: wlp3s0
- IP 213.197.188.76 => 10932 BPS - 98.31%
  GEO: [LT] Lithuania - Vilnius
  geo code:LTU region:65 Lat:54.6833 Long:25.3167 Metro: Area:
  host: cache.google.com
  isp: LT
  isp: Paneriu g. 26
  isp: LT-03209
  isp: Vilnius
  isp: LITHUANIA
  isp: UAB "Baltnetos komunikacijos"
  isp: Paneriu 26
  isp: Vilnius, Lithuania
```

# Advanced tuning:
```perl
my $snaplen = 100;  # snap only first 100 bytes of packet
my $promisc = 0;    # enable promiscious mode on interface
my $count = 100;    # packet count used for looping
```
