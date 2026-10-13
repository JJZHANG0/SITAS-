#!/usr/bin/env python3
"""Compatibility wrapper for the LSB fragile watermark algorithm."""

from lsb_watermark import *  # noqa: F401,F403
from lsb_watermark import main


if __name__ == "__main__":
    raise SystemExit(main())
