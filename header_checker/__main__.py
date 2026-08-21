"""
``python -m header_checker`` entry point.
Delegates to the CLI (use ``python -m header_checker ui`` for the web dashboard).
"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
