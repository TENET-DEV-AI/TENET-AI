"""Pytest root configuration.

Puts the repository root on sys.path once, so any test can `import services...` without its own
sys.path boilerplate and collection works the same locally and in CI.
"""

import sys
from pathlib import Path

ROOT_DIR = str(Path(__file__).resolve().parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
