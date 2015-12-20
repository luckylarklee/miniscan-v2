#!/usr/bin/python
import sys
# So, this is how you import a 'custom' module... you need an empty '__init__.py' file
# in order for this to work... however, ours is not empty! 
# Ours has a little loader script in it, so when we do the following line,
# what we're really doing is loading *ALL* the python class files in that 
# directory! This is called dynamic, or auto, loading. 
import classes
import multiprocessing

# This is just some example code showing how classes work. So, dan is an xxe class of vuln
# and we then iterate through the list of test_strings in dan... eeeaaassyyyy....
dan = classes.xss.vuln_class()
for i in dan.test_strings:
	print "Dan's test string is: ",i

# so, first we get our target from the CLI...
#target = sys.argv[1]

# Multiprocessing - like threading, but better, like...
# Let's instantiate our job list:
#jobs=[]

# Iterating scanner...
# Dynamically loads the vuln_scan() class and then dynamically
# runs the test_scan() method! :D 

if __name__ == '__main__':
	jobs=[]
	target=sys.argv[1]
	nmap = classes.mininmap.mininmap()
	domain=target.split("/")[2:3]
	open_ports=nmap.nmap_scan(domain[0])
	print "Open Ports from scan:",open_ports
	for i in classes.mod_list:
		# Remember our list of the things we loaded in the __init__.py file?
		# Well, here we're going to use that to load the modules dynamically.
		# getattr() lets you load module names and classes from a string. 
		# This means we can concat the names of modules from mod_list straight
		# into our scanner, here... and this gets automatically updated for every
		# <vuln>.py file we add to the 'classes' directory, provided that we 
		# always use the same structure, of course! :P
		# 
		# So, first, getattr the module and vuln_class:
		cls=getattr(sys.modules["classes."+i],"vuln_class")
		# Now instantiate the class:
		test_class = cls()
		# and finally, assign the test_vuln method in every class to a process... :D :D :D
		#test_class.test_vuln(target)
		scan_vuln=multiprocessing.Process(name=i,target=test_class.test_vuln, args=(target,)) 
		jobs.append(scan_vuln)
		scan_vuln.start()
	# and, as the Looney Tunes say...
	# 
	#  |_   _| |__   __ _| |_( )___    __ _| | |  / _| ___ | | | _____| |
	#    | | | '_ \ / _` | __|// __|  / _` | | | | |_ / _ \| | |/ / __| |
	#    | | | | | | (_| | |_  \__ \ | (_| | | | |  _| (_) | |   <\__ \_|
	#    |_| |_| |_|\__,_|\__| |___/  \__,_|_|_| |_|  \___/|_|_|\_\___(_)


