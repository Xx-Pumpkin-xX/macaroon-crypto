"""Use the project's patched library without modifying the Python installation."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend' / 'pymacaroons'))
sys.path.insert(0, str(ROOT / 'backend'))
