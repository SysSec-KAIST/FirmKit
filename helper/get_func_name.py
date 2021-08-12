# This script is used to obtain function address of OpenSSL functions
import glob
import os
import sys

sys.path.append(os.path.abspath("./TikNib"))
from tiknib.utils import system

func_name = "tls1_process_heartbeat"
files = glob.glob("/home/dongkwan/lastwork/openssl_dataset/*.elf")
for fname in sorted(files):
    lines = system('readelf -a {} | grep " {}"'.format(fname, func_name))
    line = lines.splitlines()[0]
    func_addr = int(line.split(" ")[1], 16)
    print(
        """  "{}":
    - {} # {}""".format(
            fname, hex(func_addr), func_name
        )
    )
