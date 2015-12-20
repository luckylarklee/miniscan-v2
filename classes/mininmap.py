# Firstly, we need to import something. Let's import ALL of scapy, the random 
# number generator, and the system library (so we can get argv).

from scapy.all import *
import random
import sys

class mininmap:


# So, we're going to write an nmap-like scanner. There's a bit of basic theory
# we'll cover along the way. But essentially, you're going to see how to write
# sockets in a way we can send a packet, and receive it.

# First we need to define end host and TCP port range. The DNS lookups etc. are
# all handled by the library. We just control the bits we *want* to control. Else,
# the scapy library has a plethora of default values to use :D


	portRange = [22,23,43,53,79,80,443,1433,2433,3389]
# ok, so what ports are we looking for? You want to memorize things? Cool - memorize
# port numbers. I know a good few - it's so handy.
#
# Here, we're going to check for the following ports: [Fill in what they're for!!]
#	22
#	23
#	43
#	53
#	79
#	80
#	443
#	1433
#	2433
#	3389
# 
	def syn_scan(self,target):
# Now we have chosen our 'victims' we're going to setup our raw sockets, as follows.
# Send SYN with random Src Port for each Dst port
		syn_ports=[]
		host = target
		for dstPort in self.portRange:
	# First, we'll use random.randint to give us a random source port address. This is
	# only so we're harder to trace ;)
			srcPort = random.randint(1025,65534)
	# Next, just like in urllib2 and httplib, we're going to setup a response handler called
	# 'resp' that is an 'srl' (source listener), is of type TCP (we're not scanning UDP yet...)
	# and has the 'S' flat set. If you want to know more, go read on 'TCP Flags' to explain.
	#
	# So, we're going to send a packet to the host, from the random source port, to the current 
	# destination port, with flag of 'S', a timeout of 1, and we're not going to ask for any details 
	# (verbose is usually 0, else you start getting information overload!)
	#
			resp = sr1(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=1,verbose=0)
	# 
	# So, like in urllib2, we just sent a thing! :D We're scanning! Now, we need to parse through
	# what we got back to decide if the port is open, closed, or filtered...
	# 
	# first up, what if we get a 'NULL' response type? Well, it's filtered...
	# 
			if (str(type(resp)) == "<type 'NoneType'>"):
				print host + ":" + str(dstPort) + " is filtered (Nothing returned)."
	# 
	# Ok, if we got something back, we need to decide what! :D We first look to see if we 'have the
	# TCP layer'. That is, we sent a 'SYN', and if we get 'ACK, SYN+1' back, we have a connection 
	# safely established with the port!! :D 
	# 
			elif(resp.haslayer(TCP)):
		# Now, the response will have its own flags, and this is how we access them. Now, the hex
		# value of 0x12 means 'SYN, ACK'. This article is quick and explains it better than I can
		# here! http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
		# 
				if(resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=host)/TCP(sport=srcPort,dport=dstPort,flags="R"),timeout=1,verbose=0)
					print host + ":" + str(dstPort) + " is open."
					# 
					# Now we add the open port to the syn_ports list. This is our main
					# goal in scanning, so we'll return the list of open ports.
					#
					syn_ports.append(dstPort)
		# 
		# Now, we hvae to deal with the situation where we have an '0x14' flag - this means 'SYN, RST', or
		# 'Synchronize and Reset' - essentially, it closed the conneciton. So, we say that his particular
		# port is closed...
		# 
				elif (resp.getlayer(TCP).flags == 0x14):
					print host + ":" + str(dstPort) + " is closed."
	# 
	# And we're done!!!! Well, we are for the TCP. Any other responsese would cause an error, but those are
	# very rare, and usually indicate a weird IDS/IPS/Honeywell magic. :P
	# 
	# So, what else is there? Well, there are ICMP packets. They have two main components; a 'type' and a 'code'.
	# RFC 792 has all the details, but essentially, what we're expecting is something of type '3', which means 
	# 'Destination Unreachable'. The second component is the 'code' which will tell us *why* the network didn't
	# let us connect. Here are the codes we're expecting:
	#	1	- Host Unreachable Error - there was no physical way to get to the host
	#	2	- Protocol Unreachable Error - this means that 'TCP' didn't work
	#	3	- Port Unreachable Error - That port ain't open on that box!!
	#	9	- Destination Network is Administratively Prohibited - this is cased by ACL's. They're not firewalls, 
	#				and this is a really good example why.
	#	10	- Destination Host is Administratively Prohibited - same as for 9, but for a specific IP
	#	13	- Communication Administratively Prohibited - this means that the router with the ACL is actively 
	#				refusing to forward your traffic... interesting! :D 
	# 
			elif(resp.haslayer(ICMP)):
				if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print host + ":" + str(dstPort) + " is filtered (silently dropped). ICMP Type 3 Code " + resp.getlayer(ICMP).code
		return syn_ports
	# 
	# Now we'll create a scanning method - this will just invoke all the other methods, and neaten up
	# our code in the main scanner thing.
	def nmap_scan(self,target):
		open_ports=[]
		try:
			open_ports=self.syn_scan(target)
		except Exception,e:
			print "ERR0R!! Nmap failed... iz you r00t?"
			print e
		return open_ports

