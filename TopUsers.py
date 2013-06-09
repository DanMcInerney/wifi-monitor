#!/usr/bin/python

from scapy.all import *
conf.verb = 0
import threading
import argparse
import sys
import signal
import commands
bash=commands.getoutput

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--number", help="Show n number of top results. Defaults to 5")
parser.add_argument("-t", "--time", help="Specify the time interval in seconds for updating packet counts. Defaults to 2s")
args = parser.parse_args()

ipr = bash('ip route')
routerRE = re.search('default via ((\d{2,3}\.\d{1,3}\.\d{1,4}\.)\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)', ipr)
interface = routerRE.group(3)
IPandMAC = []

promisc = bash('airmon-ng start %s' % interface)
monmode = re.search('monitor mode enabled on (.+)\)', promisc)
monmode = monmode.group(1)

ans,unans = arping('10.10.10.*', timeout=7)
for s,r in ans:
	hw = r[ARP].hwsrc
	ip = r[ARP].psrc
	IPandMAC.append([0, hw, ip])
print '\n[+] %s clients on the network' % len(IPandMAC)

class pktCounter(threading.Thread):
	def run(self):
		while 1:
			IPandMAC.sort(reverse=1)
			print '\n'
			def printer(n):
				for x in range(n):
					try:
						print IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2]
					except:
						pass
			if args.number:
				printer(int(args.number))
			else:
				printer(5)
			if args.time:
				time.sleep(int(args.time))
			else:
				time.sleep(2)

c = pktCounter()
c.daemon = True
c.start()

def main(pkt):
	if pkt.haslayer(Dot11):
		pkt = pkt[Dot11]
#		type 2 is Data, type 0 is Management
		if pkt.type == 2 and pkt.addr1 != '68:94:23:79:08:df' and pkt.addr2 != '68:94:23:79:08:df':
			hw = pkt[Dot11].addr1
			for idx,x in enumerate(IPandMAC):
				if hw in x:
					IPandMAC[idx][0] = IPandMAC[idx][0]+1

	def signal_handler(signal, frame):
		print 'leaning up monitor mode...'
		ipforwardoff = bash('airmon-ng stop mon0')
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)

sniff(iface=monmode, prn=main)
