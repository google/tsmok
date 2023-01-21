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

"""Interface for device class."""

import abc
import logging
import tsmok.emu.arm as arm


class DeviceBase(abc.ABC):
  """Basic class for a specific device HW implementation."""

  def __init__(self, name, log_level=logging.ERROR):
    self.name = name
    self.log = logging.getLogger(f'[DEVICE][{name}]')
    self.log.setLevel(log_level)

  @abc.abstractmethod
  def register(self, emu: arm.ArmEmu):
    raise NotImplementedError()

  def write_trace(self, emu, addr, size, value):
    del emu  # unused in this call
    self.log.debug('Write 0x%x-0x%x: 0x%x',
                   addr, addr + size - 1, value)

  def read_trace(self, emu, addr, size, value):
    del emu  # unused in this call
    self.log.debug('Read 0x%x-0x%x: 0x%x',
                   addr, addr + size - 1, value)

