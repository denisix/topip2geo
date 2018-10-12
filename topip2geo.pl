#!/usr/bin/perl
use Net::Pcap;
use NetPacket::IP;
use NetPacket::UDP;
use NetPacket::TCP;
use NetPacket::IP qw(:protos);
use NetPacket::Ethernet;
use Time::HiRes qw( gettimeofday tv_interval );
use Data::Dumper;
use Geo::IP::PurePerl;
use Socket;

my $dev = $ARGV[0] || 'eth0';
my $mac;

my $geo_file = '/tmp/GeoLiteCity.dat';

if (! -e $geo_file ) {
	print "Loading GeoIP database..\n";
	system("wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz -O $geo_file.gz && gunzip $geo_file");
}
my $geo = Geo::IP::PurePerl->new($geo_file, GEOIP_MEMORY_CACHE);

# gather mac
open IO, "ip li sh $dev|";
while(<IO>) {
	if (/ether\s+([\w\d\:]+)\s+/) {
		$mac = $1;
		print "$dev mac = $mac\n";
		last;
	} 	
}
close IO;

my $snaplen = 100;	# snap only first 100 bytes of packet
my $promisc = 0;	# enable promiscious mode on interface
my $to_ms   = 0;	# 
my $count = 100;	# packet count used for looping

my $n;
my %hash;

if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}
print "Listen: $dev\n";

my $t0;
my $filter_compiled;
my $last_ip;

while (1) {
	$n = 0;
	%hash = ();
	undef %hash;
	my $pcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err) or die "cant open_live: $err";
	Net::Pcap::compile($pcap, \$filter_compiled, "ether dst $mac && ip", 1, $netmask) && die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($pcap, $filter_compiled) && die 'Unable to set packet capture filter';

	$t0 = [gettimeofday];
	Net::Pcap::loop($pcap, $count, \&process_packet, ''); 
	Net::Pcap::close($pcap);
	$elapsed = tv_interval ($t0);
	get_stats();
}

sub process_packet {
 	my($user_data, $header, $packet) = @_;
	my $ether = NetPacket::Ethernet::strip($packet);
	my $ip = NetPacket::IP->decode($ether);
	#print "$n: SRC ". $ip->{'src_ip'} ."\n";
	my $src = $ip->{'src_ip'};
	$hash{$src}+=$ip->{'len'};
	$n+= $ip->{'len'};
};

sub get_stats() {
	$elapsed = tv_interval ( $t0 );
	#print "n = $n\nelapsed = $elapsed sec\n" if $debug;
	my $perc;
	foreach $ip (sort {$hash{$b} <=> $hash{$a}} keys %hash) {
		$perc = int(10000*$hash{$ip}/$n)/100;
		if ($perc > 50) {

			if ($lastip ne $ip) {
				$lastip = $ip;

				$pps = int($hash{$ip} / $elapsed);
				my $code = $geo->country_code3_by_addr($ip);
				my $country = $geo->country_name_by_addr($ip);
				my ($country_code,$country_code3,$country_name,$region,$city,$postal_code,$latitude,$longitude,$metro_code,$area_code ) = $geo->get_city_record($ip);
				#my $r = $geo->record_by_addr($ip);
				print "- IP $ip => $pps BPS - $perc%\n";
				print "  GEO: [$country_code] $country_name - $city\n";
				print "  geo code:$country_code3 region:$region Lat:$latitude Long:$longitude Metro:$metro_code Area:$area_code\n";
				$iaddr = inet_aton($ip); # or whatever address
				$host  = gethostbyaddr($iaddr, AF_INET);
				print "  host: $host\n" if $host ne '';
				open IO, "whois $ip|";
				while(<IO>) {
		        		if (/country|city|address/) {
						s/(country|city|address)\s*:\s*//;
		                		print "  isp: $_";
			        	}
				}
				close IO;
				print "\n";
			}
		}
	}
}
