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

"""Base class for binary images."""

import abc
import io


class Image(abc.ABC):
  """Represent the loaded to emulator a binary image."""

  def __init__(self, image: io.BufferedReader, load_addr: int):
    self.name = image.name
    self.text_start = None
    self.text_end = None
    self.entry_point = None
    self.mem_regions = []
    self.func_symbols = dict()
    self.load_offset = 0

    self._load(image, load_addr)

  @abc.abstractmethod
  def _load(self, image: io.BufferedReader, load_addr: int) -> None:
    raise NotImplementedError()
