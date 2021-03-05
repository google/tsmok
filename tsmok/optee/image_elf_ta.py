"""OPTEE TA ELF binary image."""

import io

import tsmok.common.image_elf as image_elf
import tsmok.optee.image_ta as image_ta


class TaElfImage(image_elf.ElfImage, image_ta.TaImage):
  """Defines TA ELF binary file."""

  def __init__(self, image: io.BufferedReader, load_addr: int = None):
    image_ta.TaImage.__init__(self)
    image_elf.ElfImage.__init__(self, image, load_addr)

  def _parse_sections(self, image: io.BufferedReader):
    ta_hdr_data = self._get_section_data('.ta_head')
    ta_hdr = self._parse_ta_header(ta_hdr_data)
    # Modern OPTEE TA binaries does not provide entry point via .ta_head
    # In this case UINT64MAX value is returned.
    # ELF entry point has to be used instead.
    if ta_hdr.entry_offset == 0xffffffffffffffff:
      self.entry_point = self._convert_vaddr_to_paddr(
          self._elf.header['e_entry'])
    else:
      self.entry_point = self._convert_vaddr_to_paddr(ta_hdr.entry_offset)
    self.stack_size = ta_hdr.stack_size
    self.uuid = ta_hdr.uuid

    addr, size = self._get_section_info('.text')
    self.text_start = self._convert_vaddr_to_paddr(addr)
    self.text_end = self.text_start + size - 1
