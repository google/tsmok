"""ATF TEE implementation."""

import abc
import logging
from typing import List

import tsmok.common.error as error


class Atf(abc.ABC):
  """Implementation of Atf."""

  def __init__(self, name='ATF',
               log_level=logging.ERROR):
    self.name = name
    self.mem_regions = list()

    self._log = logging.getLogger(f'[{name}]')
    self._log.setLevel(log_level)
    self._callbacks = dict()

    self._setup()

  @abc.abstractmethod
  def _setup(self):
    # Trustes OS calls
    raise NotImplementedError()

  def _args_dump(self, args: List[int]) -> None:
    self._log.info('Args:')
    for i in range(len(args)):
      self._log.info('\targs[%d]: 0x%08x', i, args[i])

  def smc_handler(self, tee, flag, call, args):
    try:
      self._log.debug('.exec. => SMC: 0x%08x', call)
      ret = self._callbacks[call](tee, flag, args)
      self._log.debug('.exec. <= SMC: 0x%08x ret 0x%08x', call, ret)
    except KeyError:
      raise error.Error(f'Unhandled Smc call (0x{call:08x}).')

    return ret
