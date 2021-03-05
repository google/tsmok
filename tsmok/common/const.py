"""Common constants."""

import enum
import logging


PAGE_SIZE = 4096


class LogLevelCustom(enum.IntEnum):
  DEBUG_MEM = logging.DEBUG - 1
  DEBUG_DISASM = logging.DEBUG - 2
  TRACE = logging.NOTSET + 1
