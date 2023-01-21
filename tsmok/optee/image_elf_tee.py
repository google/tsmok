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

"""OPTEE TA ELF binary image."""

import io

import tsmok.common.error as error
import tsmok.common.image_elf as image_elf
import tsmok.common.memory as memory


class TeeElfImage(image_elf.ElfImage):
  """Defines OPTEE TEE ELF binary file."""

  THREAD_INIT_FUNC = 'thread_init_boot_thread'
  THREAD_CLEAR_FUNC = 'thread_clr_boot_thread'
  PUSH_SESSION_FUNC = 'ts_push_current_session'
  POP_SESSION_FUNC = 'ts_pop_current_session'
  START_FUNC = '_start'

  def __init__(self, image: io.BufferedReader, load_addr: int = None):
    image_elf.ElfImage.__init__(self, image, load_addr)
    self.thread_init = None
    self.thread_clear = None
    self.push_session = None
    self.pop_session = None
    self._get_func_addresses()

  def _get_func_addresses(self):
    for addr, name in self.func_symbols.items():
      if name == self.THREAD_INIT_FUNC:
        self.thread_init = self._convert_vaddr_to_paddr(addr)
      elif name == self.THREAD_CLEAR_FUNC:
        self.thread_clear = self._convert_vaddr_to_paddr(addr)
      elif name == self.START_FUNC:
        self.entry_point = self._convert_vaddr_to_paddr(addr)
      elif name == self.PUSH_SESSION_FUNC:
        self.push_session = self._convert_vaddr_to_paddr(addr)
      elif name == self.POP_SESSION_FUNC:
        self.pop_session = self._convert_vaddr_to_paddr(addr)

      if all([self.thread_init, self.thread_clear, self.entry_point,
              self.push_session, self.pop_session]):
        break

    if not self.entry_point:
      raise error.Error('Wrong TEE Elf: does not have all of '
                        'entry point function')

  def _parse_sections(self, image: io.BufferedReader):
    addr, size = self._get_section_info('.text')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1

  def _inject_data(self, sym_name: str, data: bytes):
    inject_addr = None
    inject_size = None
    for symbol in self._symbols():
      if symbol['st_info']['type'] == 'STT_OBJECT':
        if symbol.name == sym_name:
          inject_addr = self._convert_vaddr_to_paddr(symbol['st_value'])
          inject_size = symbol['st_size']
          break

    if (not inject_addr) or (not inject_size):
      raise error.Error(f'File {self.name} wrong image: can\'t find {sym_name}')

    if inject_size < len(data):
      raise error.Error('Wrong injected data size: '
                        f'{len(data)} > {inject_size}')

    found = False
    for reg in self.mem_regions:
      if reg.start <= inject_addr < (reg.start + reg.size):
        off = inject_addr - reg.start

        if isinstance(reg, memory.MemoryRegionData):
          found = True
          # inject provided date
          txt = bytearray(reg.data)
          txt[off:off + len(data)] = data
          reg.data = bytes(txt)

    if not found:
      raise error.Error('Failed to find MemoryRegionData to inject data')

  def get_mem_info_from_session_id(self, emu, sid: int):
    raise NotImplementedError()
