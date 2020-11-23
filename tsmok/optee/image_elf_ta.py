"""OPTEE TA ELF binary image."""

import collections
import io
import struct
import uuid

import tsmok.common.image_elf as image_elf


TaHeader = collections.namedtuple('TaHeader',
                                  ['uuid', 'stack_size', 'flag',
                                   'entry_offset'])


class TaElfImage(image_elf.ElfImage):
  """Defines TA ELF binary file."""

  def __init__(self, image: io.BufferedReader):
    self.stack_size = None
    self.uuid = None
    image_elf.ElfImage.__init__(self, image)

  def _parse_ta_header(self, data: bytes):
    # TA_UUID
    stack_size, flags, ptr = struct.unpack('<2IQ', data[16:])

    arg0, arg1, arg2 = struct.unpack('I2H', data[:8])
    arg3 = struct.unpack('>Q', data[8:16])[0]
    uid = uuid.UUID(int=(arg0 << 96) | (arg1 << 80) | (arg2 << 64) | arg3)

    return TaHeader(uid, stack_size, flags, ptr)

  def _parse_sections(self, image: io.BufferedReader):
    ta_hdr_data = self._get_section_data('.ta_head')
    ta_hdr = self._parse_ta_header(ta_hdr_data)
    self.entry_point = self._convert_vaddr_to_paddr(ta_hdr.entry_offset)
    self.stack_size = ta_hdr.stack_size
    self.uuid = ta_hdr.uuid

    addr, size = self._get_section_info('.text')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1
