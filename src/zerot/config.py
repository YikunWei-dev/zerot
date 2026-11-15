"""zerot — optional configuration loading (software mode).

Configuration is a simple JSON file. Every key is optional and falls back to
the CLI default when omitted.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

DEFAULT_CONFIG_NAME = ".zerot.json"


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    if path is None:
        path = os.path.join(os.getcwd(), DEFAULT_CONFIG_NAME)
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}
