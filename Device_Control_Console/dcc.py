#!/usr/bin/env python
"""Entry point so the tool runs from a checkout without installing anything.

    python dcc.py                 # start the web console
    python dcc.py resolve 1038    # command line
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dcc.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
