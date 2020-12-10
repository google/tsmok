"""Common constants."""

import enum
import logging


class LogLevelCustom(enum.IntEnum):
  DEBUG_MEM = logging.DEBUG - 1
  DEBUG_DISASM = logging.DEBUG - 2
  TRACE = logging.NOTSET + 1
