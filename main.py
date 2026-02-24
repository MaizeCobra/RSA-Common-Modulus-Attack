"""
main.py
-------
Entry point for the RSA Common Modulus Attack demonstration.

Usage:
    python main.py
"""

import sys
import os

# Ensure the project directory is on the path
sys.path.insert(0, os.path.dirname(__file__))

from gui import launch

if __name__ == "__main__":
    launch()
