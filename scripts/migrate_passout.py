#!/usr/bin/env python3
"""
Migrate passwords from the PassOut password manager.

Usage:
   migrate_passout.py <src-dir> <dest-dir>
"""

import sys
import os
import toml
from subprocess import Popen, PIPE


def convert_file(filename, dest_dir):
    with open(filename, "rb") as fh:
        p = Popen(["gpg2", "--enarmor"], stdin=fh, stdout=PIPE)
    cipher_text, stderr = p.communicate()
    assert(p.returncode == 0)

    new_data = {
        "user": None,
        "email": None,
        "comment": None,
        "cipher_text": cipher_text.decode("utf-8"),
    }

    base = os.path.basename(filename)
    assert(base.endswith(".gpg"))
    base = base[:-4] + ".toml"
    elems = base.split("__")
    new_path = os.path.join(dest_dir, *elems)
    parent = os.path.dirname(new_path)
    os.makedirs(parent, exist_ok=True)

    with open(new_path, "w") as fh:
        toml.dump(new_data, fh)


def main(src_dir, dest_dir):
    for fl in os.listdir(src_dir):
        path = os.path.join(src_dir, fl)
        if not os.path.isfile(path):  # skip syncthing dir.
            continue
        convert_file(path, dest_dir)


if __name__ == "__main__":
    try:
        src_dir, dest_dir = sys.argv[1:]
    except (IndexError, ValueError):
        print(__doc__)
        sys.exit(1)
    main(src_dir, dest_dir)
