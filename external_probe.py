#!/usr/bin/env python3
"""Launch the external verification companion."""

import sys

from server_audit.external_probe import main


if __name__ == "__main__":
    sys.exit(main())
