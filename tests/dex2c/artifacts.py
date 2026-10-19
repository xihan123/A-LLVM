"""Compatibility import for the shared production artifact verifier."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from dex2c_artifacts import Dex, verify_wrappers
