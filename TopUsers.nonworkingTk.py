#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import argparse
import sys
import signal
import commands
import threading
from Tkinter import *
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
timer1 = time.time()
timer2 = 0
wired = 0
changed = []

choice = raw_input('Wired or wirelessly connected? [1/2]: ')
if choice == '1':
	wired = 1

if wired == 1:
	pass
else:
	promisc = bash('airmon-ng start %s' % interface)
	monmode = re.search('monitor mode enabled on (.+)\)', promisc)
	monmode = monmode.group(1)
	print '\n[+] Enabled monitor mode'

ans,unans = arping(IPprefix+'*', timeout=5)
for s,r in ans:
	hw = r[ARP].hwsrc
	ip = r[ARP].psrc
	IPandMAC.append([0, hw, ip])

print '\n[+] %s clients on the network' % len(IPandMAC)

t = 0
for idx,x in enumerate(IPandMAC):
	if routerIP in x:
		routerMAC = IPandMAC[idx][1]
		t=1
if t == 0:
	monOff = bash('airmon-ng stop %s' % monmode)
	sys.exit('Router MAC not found')

#Create Tkinter GUI
class popup:

	def __init__(self, master):

			frame = Frame(master)
			frame.pack()

			self.button1 = Button(frame, text="1", command=self.func1)
			self.button1.pack(side=LEFT)

			self.button2 = Button(frame, text="2", command=self.func2)
			self.button2.pack(side=LEFT)

			self.button3 = Button(frame, text="3", fg='red', command=self.func3)
			self.button3.pack(side=LEFT)

	def func1(self):

		if wired == 1:
			sniff(iface=interface, prn=main, store=0)
		else:
			try:
				sniff(iface=monmode, prn=main, store=0)
			except socket.error:
				print 'Could not reach network'
			except Exception:
				raise

		text = Text(root)
		text.pack()
		text.insert(END, printer(n))

	def func2(self):

		print 'func2'
		text = Text(root)
		text.pack()
		text.insert(END, yourobjecthere)

	def func3(self):

		print 'func3'
		text = Text(root)
		text.pack()
		text.insert(END, yourobjecthere)


def newclients(pkt):
	global IPandMAC
	newIP = ''
	newMAC = ''
#	hostname = ''
	if pkt.haslayer(DHCP) and pkt.haslayer(Ether):
		#Check for message-type == 3 which is the second request the client makes
		if pkt[DHCP].options[0][1] == 3:
			opt = pkt[DHCP].options
			for idx,x in enumerate(opt):
#				if "hostname" in repr(x):
#					hostname = opt[idx][1]
				if "requested_addr" in repr(x):
					newIP = opt[idx][1]
					newMAC = pkt[Ether].src
					if newIP != '' and newMAC != '':
						print '\n[!]',newMAC,'at',newIP,'joined the network'
						for idy,y in enumerate(IPandMAC):
							if newIP == IPandMAC[idy][2]:
								return
					IPandMAC.append([0, newMAC, newIP])

#				print newIP, newMAC
#				if newIP != '' and newMAC != '' and not host:
#					print '[+]',newIP, newMAC,'joined the network'

class newDevices(threading.Thread):
	def run(self):
		sniff(store=0, filter='port 67 or 68', prn=newclients, iface=interface)

def printer(n):
	global changed
	print ''
	for x in range(n):
		if IPandMAC[x][0] in changed:
			if IPandMAC[x][2] == routerIP:
				print '[+]',IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2],'(router)'
			else:
				print '[+]',IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2]
		else:
			try:
				if IPandMAC[x][2] == routerIP:
					print '[-]',IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2],'(router)'
				else:
					print '[-]',IPandMAC[x][0], IPandMAC[x][1], IPandMAC[x][2]
			except:
				changed = []
				pass
	changed = []

def timearg(t):
	global timer1
	if timer2 > timer1+t:
		IPandMAC.sort(reverse=1)
		if args.number:
			printer(int(args.number))
		else:
			printer(5)
		timer1 = time.time()

nd = newDevices()
nd.daemon = True
nd.start()

def main(pkt):
	global timer2
	global changed

	#type 2 is Data, type 0 is Management
	if pkt.haslayer(Dot11):
		if pkt[Dot11].type == 2:
			pkt = pkt[Dot11]
			for i in [pkt.addr1, pkt.addr2]:
				if i in [localMAC, 'ff:ff:ff:ff:ff:ff']:
					return
			srcMAC = pkt.addr1
			dstMAC = pkt.addr2
			for idx,x in enumerate(IPandMAC):
				#Below comment triggers the packet counter for everyone??
				#if srcMAC or dstMAC == x[1]:
				if srcMAC == x[1] or dstMAC == x[1]:
					IPandMAC[idx][0] = IPandMAC[idx][0]+1
					changed.append(IPandMAC[idx][0])
			timer2 = time.time()
			if args.time:
				timearg(int(args.time))
			else:
				timearg(2)

		def signal_handler(signal, frame):
			print 'leaning up...'
			if wired == 1:
				pass
			else:
				monOff = bash('airmon-ng stop %s' % monmode)
			#arp tables seem to get messed up when starting and stopping monitor mode so this heals the arp tables
			print 'restoring arp table...'
			arpRestore = bash('arp -s routerIP routerMAC')
			sys.exit(0)
		signal.signal(signal.SIGINT, signal_handler)

root = Tk()
root.title('Title!')
app = popup(root)
Label(root,text='Label').pack(pady=10)
root.mainloop()

#if wired == 1:
#	sniff(iface=interface, prn=main, store=0)
#else:
#	try:
#		sniff(iface=monmode, prn=main, store=0)
#	except socket.error:
#		print 'Could not reach network'
#	except Exception:
#		raise

