from vulns import *

class vuln_class(vuln):
	vuln_name="[XSS]"
	# So, we've created this class wit hthe argument 'vuln', which tells python that it's a
	# child class of the vuln class. As such, everything we defined above is already here.
	# We can change things before calling methods/variables/etc.
	# 
	# So, we start by defining our test strings:
	test_strings = ["test-string-asdf1234ASDF","<test>","<script>alert(1)</script>"]
	# And here we define our pos responses - which will be the same!
	responses_pos = ["test-string-asdf1234ASDF","<test>","<script>alert(1)</script>"]
	
	def test_vuln(self,target):
		print "Scanning for XSS..."
		# First check if the page is live:
		if not self.live_test(target):
			return
		# Now run some tests:
		xss_test=self.send_scan_append(target)
		# So, now xss_test is a list of responses. If that list is empty,
		# it means that we errored out, so we just go to the next scan
		if xss_test is None:
			return
		# However, if we managed to get some responses, then we can now 
		# Go through the reponses...
		for i in xss_test:
			# and in each response, go through our list of positive strings...
			for j in self.responses_pos:
				# ...and if we find one, then we got a response with a positive
				# string in... and you know what that means!! Pwned! :D
				if j in i:
					print self.vuln_name,"VULN String "+i+" Returned in page"
