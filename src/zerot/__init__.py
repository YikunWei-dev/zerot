"""zerot — detect dangerous Unicode characters in source code."""

__version__ = "1.0.0"

from .catalog import CATEGORIES
from .engine import Finding, ScanResult, scan

__all__ = ["scan", "Finding", "ScanResult", "CATEGORIES", "__version__"]
