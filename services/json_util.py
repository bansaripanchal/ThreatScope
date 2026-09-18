"""
ThreatScope V2 - Safe JSON Normalization & Serialization Utility
Recursively normalizes all reconnaissance data, timestamps, sets, tuples, bytes,
enums, and Jinja Undefined objects into valid, standard JSON types before serialization.
"""

import json
import socket
import datetime
import ipaddress
from enum import Enum
from typing import Any

def normalize_for_json(val: Any) -> Any:
    """
    Recursively normalizes any Python value to pure standard JSON-serializable types:
    dict, list, str, int, float, bool, None.
    Converts:
    - None -> None
    - Jinja Undefined -> None
    - datetime.datetime / datetime.date -> ISO 8601 formatted string
    - bytes -> UTF-8 decoded string
    - set, frozenset, tuple -> list of normalized values
    - dict -> dict with string keys and normalized values
    - Enum -> enum.value
    - Exception -> str(exception)
    - IP/Socket objects -> str representation
    """
    if val is None:
        return None

    # Check for Jinja2 Undefined without requiring hard jinja2 import
    if type(val).__name__ in ("Undefined", "StrictUndefined", "DebugUndefined"):
        return None

    if isinstance(val, (bool, int, float, str)):
        return val

    if isinstance(val, (datetime.datetime, datetime.date)):
        return val.isoformat()

    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")

    if isinstance(val, (set, frozenset, tuple, list)):
        return [normalize_for_json(item) for item in val]

    if isinstance(val, dict):
        return {str(k): normalize_for_json(v) for k, v in val.items()}

    if isinstance(val, Enum):
        return val.value

    if isinstance(val, (ipaddress._BaseAddress, ipaddress._BaseNetwork)):
        return str(val)

    if isinstance(val, (socket.socket, Exception)):
        return str(val)

    if hasattr(val, "__dict__"):
        try:
            return normalize_for_json(vars(val))
        except Exception:
            return str(val)

    # Fallback to string representation for any unknown custom object
    return str(val)


def safe_json_dumps(val: Any, **kwargs) -> str:
    """
    Serializes any object to a JSON string after recursive normalization.
    Guarantees no TypeError on Undefined, datetimes, sets, or non-primitive objects.
    """
    normalized = normalize_for_json(val)
    return json.dumps(normalized, default=str, **kwargs)


def safe_json_loads(raw: str, default: Any = None) -> Any:
    """Safely deserializes a JSON string with fallback default on malformed data."""
    if not raw or not isinstance(raw, str):
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except Exception:
        return default if default is not None else {}
