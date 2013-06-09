#!/usr/bin/python

from scapy.all import *
conf.verb = 0
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
routerIP = routerRE.group(1)
IPprefix = routerRE.group(2)
interface = routerRE.group(3)
localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
localMAC = get_if_hwaddr(interface)
IPandMAC = []

promisc = bash('airmon-ng start %s' % interface)
monmode = re.search('monitor mode enabled on (.+)\)', promisc)
monmode = monmode.group(1)

ans,unans = arping(IPprefix+'*', timeout=7)
for s,r in ans:
	hw = r[ARP].hwsrc
	ip = r[ARP].psrc
	IPandMAC.append([0, hw, ip])
for idx,x in enumerate(IPandMAC):
	if routerIP in x:
		routerMAC = IPandMAC[idx][1]

print '\n[+] %s clients on the network' % len(IPandMAC)

timer1 = time.time()
timer2 = 0

def printer(n):
	print '\n'
	for x in range(n):
		try:
			print IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2]
		except:
			pass

def timearg(t):
	global timer1
	if timer2 > timer1+t:
		IPandMAC.sort(reverse=1)
		if args.number:
			printer(int(args.number))
		else:
			printer(5)
		timer1 = time.time()

def main(pkt):
	global timer2
	if pkt.haslayer(Dot11):
		pkt = pkt[Dot11]
#		type 2 is Data, type 0 is Management
		if pkt.type == 2 and pkt.addr1 != localMAC and pkt.addr2 != localMAC:
			hw = pkt[Dot11].addr1
			for idx,x in enumerate(IPandMAC):
				if hw in x:
					IPandMAC[idx][0] = IPandMAC[idx][0]+1
			timer2 = time.time()
			if args.time:
				timearg(int(args.time))
			else:
				timearg(2)

	def signal_handler(signal, frame):
		print 'leaning up monitor mode...'
		ipforwardoff = bash('airmon-ng stop %s' % monmode)
		#arp tables seem to get messed up when starting and stopping monitor mode so this heals the arp tables
		a = send(ARP(op="is-at", pdst=localIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
		sys.exit(0)
	signal.signal(signal.SIGINT, signal_handler)

sniff(iface=monmode, prn=main, store=0)
