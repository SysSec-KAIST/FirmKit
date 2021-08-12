import os
import sys
import shutil

sys.path.append(os.path.abspath("./TikNib"))
from tiknib.utils import system, do_multiprocess


prefix = "/home/dongkwan/lastwork/firmkit/output/"
new_prefix = "/home/dongkwan/lastwork/firmkit/output_idbs/"


def copy_helper(fname):
    new_fname = fname.replace(prefix, new_prefix)
    dir_name = os.path.dirname(new_fname)
    os.makedirs(dir_name, exist_ok=True)
    shutil.copy(fname, new_fname)


def main():
    with open("out.txt", "r") as f:
        files = f.read().splitlines()

    results = do_multiprocess(
        copy_helper,
        files,
        threshold=1,
    )


if __name__ == "__main__":
    main()
