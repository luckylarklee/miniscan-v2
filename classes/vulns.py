# Import the useful stuff...
import requests
import urllib2
import random
import re

# So, this is where we'll define the 'magic' :P
# 
# The aim is to build a basic, functioning, no fuss scanner. To do this, we have 'scanner.py',
# and this just organises the what vulns are processed where. The real work is done here, in
# the 'vulns.py' file. 
# 
# The structure is this:
# 	Base class of 'vuln' - this defines all the basic pieces of a vuln. The title, description, 
#		CVSS score and vector, as well as the basic scanning functions, send_scan_append, which 
#		appends an attack sring to a URL, and send_scan_append, which puts an attack string in
#		a POST request.
#	Vuln classes - here, we define the required specifics for each vuln type. So, XSS doesn't 
#		really have any 'negative response' strings; either the stuff gets reflected or it doesn't
#		(Yes, I'm ignoring DOM based XSS here). 
#
# Now that we have this, we can define child classess. These will inherit all the 'pieces' of 
# the vuln class, and then add their own funtionality and variables. So, they'll usually replace
# the response_pos and response_neg lists appropriately. If they don't then the lists are still 
# there, they're just blank.
#
# Note, this framework currently doesn't support time-based blind SQLi. This wouldn't be too hard 
# build in, but it's not there at the moment.
# 
# Also, at some point, we're going to replace the fixed response strings with response regex - 
# that way we can just regex the output for relevant strings. :D But this is a future problem...
# 
class vuln:
	vuln_name=""
	# here we need to put the standard vuln types and requirements
	# First up is CVSS - by the standard, it needs the score *and* vector
	cvss_score = 10.0
	cvss_vector= "AV:N/AC:L/AU:N/C:C/I:C/A:C"
	# Now a title and Vuln Description
	vuln_title = "Very Serious Problem"
	vuln_desc = "You have a very serious problem."
	# Now define what the test strings list should look like:
	test_strings = [""]
	# as well as the pos and neg response strings:
	responses_pos = [""]
	responses_neg = [""]
	# This is a testing function - it tests the connection, and if the site gives
	# a non-error HTTP response (as in, NOT codes 4xx (401, 403, 404, 418, etc.) 
	# then we can declare that the site is 'live'. We do this by returning a 
	# boolean of 'True' if it's live. Else, we print the error and GTFO!!
	def live_test(self,target):
		try:
			izlive = urllib2.urlopen(target).read()
		except Exception, e:
			print "Host not live or target not valid"
			print "ERR0R: ",e
			return False
		# If we didn't error out, and we got some data back, then we'll continue.
		if izlive is not None:
			print self.vuln_name,": Target Acquired..."
			return True
		# If we didn't error but got no data, then we're not really testing anything,
		# potentially, so we'll just say 'false' to getting data, and deal with what
		# that might 'mean' later on...
		else:
			return False
	# Now define some scanning methods.
	# Here's one...
	def send_scan_append(self,target):
		# We're going to return a list of responses from our test strings
		resp_list = []
		# Now, we pull the test_strings from whatever child class we're currently in:
		for i in self.test_strings:
			# ... and we try and send them.
			try:
				print self.vuln_name+": Sending "+i
				# Here comes the magic...
				response = urllib2.urlopen(target+i).read()
				# This is in case we get a blank repsonse... urllib2 handles errors by 
				# giving blank responses...
				if response is not None:
					# However, if we have some data, add it to the end of the list:
					resp_list.append(response)
			#This bit is for any issues with the HTTP request - just a generic error handler
			except Exception, e:
				# OHNOES!!
				print self.vuln_name+": Error in sending Payload "+i
				print self.vuln_name,e
				# KTHXCARRYON
				continue
		# WE DUN? Ok, send back what we found...
		return resp_list
		# KTHXBAI
	# Here's another... Fewer comments as it's essentially the same:
	def send_scan_body(self,target):
		resp_list = []
		for i in self.test_strings:
			try:
				print self.vuln_name+": Sending "+i
				response = urllib2.urlopen(target,i).read()
				if response is not None:
					resp_list.append(response)
			except Exception, e:
				print self.vuln_name+": Error in sending Payload "+i
				print self.vuln_name,e
				continue
		return resp_list
	def timed_response(self,target):
		return target


	


