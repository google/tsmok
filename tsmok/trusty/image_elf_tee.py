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

"""Trusty TA ELF binary image."""

import io

import tsmok.common.error as error
import tsmok.common.image_elf as image_elf


class TrustyElfImage(image_elf.ElfImage):
  """Defines Trusty TEE ELF binary file."""

  START_FUNC = '_start'

  def __init__(self, image: io.BufferedReader, load_addr: int = None):
    image_elf.ElfImage.__init__(self, image, load_addr)
    self._get_func_addresses()

  def _get_func_addresses(self):
    for addr, name in self.func_symbols.items():
      if name == self.START_FUNC:
        self.entry_point = self._convert_vaddr_to_paddr(addr)

      if self.entry_point:
        break

    if not self.entry_point:
      raise error.Error('Wrong Trusty TEE Elf: does not have all of '
                        'entry point function')

  def _parse_sections(self, image: io.BufferedReader):
    addr, size = self._get_section_info('.text')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1
