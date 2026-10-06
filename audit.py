#!/usr/bin/env python3
"""Launch the host audit."""

import sys

from server_audit.cli import main


if __name__ == "__main__":
    sys.exit(main())
