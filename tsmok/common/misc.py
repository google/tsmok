# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Miscellaneous helper functions."""

from typing import Dict, Any


def get_next_available_key(d: Dict[int, Any]) -> int:
  if not d:
    return 1

  r = [ele for ele in range(1, max(d.keys()) + 1) if ele not in d.keys()]

  if not r:
    return max(d.keys()) + 1

  return r[0]

