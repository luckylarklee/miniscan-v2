from vulns import *

# So, here's a sample vuln class without all the comments so you can read it cleanly.
class vuln_class(vuln):
        vuln_name="[SQLi]"
	test_strings = ["\'","\'+--+"]
        responses_pos=["ERROR","Error","SQL"]
        responses_neg=["SAMESIMSCANNER"]

        def test_vuln(self,target):
                print "Scanning for SQLi..."
                if not self.live_test(target):
                        return
                sqli_test=self.send_scan_body(target)
                sqli_test2=self.send_scan_append(target)
                for i in sqli_test2:
                        xxe_test.append(i)
                if sqli_test is None:
                        return
                for i in sqli_test:
                        for j in self.responses_pos:
                                if j in i:
                                        print self.vuln_name,"VULN!"

