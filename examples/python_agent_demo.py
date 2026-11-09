#!/usr/bin/env python3
"""Compatibility entry point for the side-effect-free first-BLOCK demo.

Use `node scripts/first-block.mjs` from the repository root to start the local
Worker and run both installed clients. See docs/FIRST_BLOCK.md for setup.
"""
import os

from first_block import main


if __name__ == "__main__":
    if not os.environ.get("VIZIER_BASE_URL"):
        raise SystemExit("Start the local demo with: node scripts/first-block.mjs (see docs/FIRST_BLOCK.md)")
    main()
