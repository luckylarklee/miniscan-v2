from os import listdir
from os.path import dirname,abspath,isfile,basename
import glob

mods = listdir(".")
mod = glob.glob(dirname(abspath(__file__))+"/*.py")
modules = [basename(f)[:-3] for f in mod if isfile(f)]
print mods
print mod
print modules

