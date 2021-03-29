"""Miscellaneous helper functions."""

from typing import Dict, Any


def get_next_available_key(d: Dict[int, Any]) -> int:
  if not d:
    return 1

  r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

  if not r:
    return max(d.keys()) + 1

  return r[0]

