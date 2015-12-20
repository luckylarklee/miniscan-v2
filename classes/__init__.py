# 
# AutoLoader - we'll load all of our files automatically into
# the scanner. We can then run our test_run() methods all at once.
#

import os
# this will be the list of active modules in the 'classes' module
mod_list=[]
for module in os.listdir(os.path.dirname(__file__)):
	if module == '__init__.py' or module[-3:] != '.py':
		continue
	__import__(module[:-3], locals(), globals(),['*'])
	mod_list.append(module[:-3])
del module
mod_list.remove("vulns") 
mod_list.remove("mininmap") 
