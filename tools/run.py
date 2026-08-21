#!/usr/bin/env python3
"""Generate a Delphi WARP library.

    python3 run.py <kb.bin> <workdir> <out.warp>
"""

import sys

import binaryninja as bn

from tools import generate

if __name__ == "__main__":
    bn.disable_default_log()
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    generate.generate(sys.argv[1], sys.argv[2], sys.argv[3],
                      log=lambda m: print(m, flush=True))
