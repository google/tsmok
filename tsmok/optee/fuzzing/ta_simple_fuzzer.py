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

"""OPTEE TA fuzzing."""

import enum
import logging
import struct

import tsmok.common.error as error
import tsmok.common.ta_error as ta_error
import tsmok.optee.error as optee_error
import tsmok.optee.utee_args as utee_args


class TaSimpleFuzzer:
  """AFLPlusPlus compatible TA fuzzer wrapper."""

  SESSION_ID = 1

  FUNC_FMT = '<2I'
  HDR_FMT = '<IH'
  PARAM_INT_FMT = '<2I'
  PARAM_BUFFER_FMT = '<I'

  OPTEE_NUM_PARAMS = 4

  class Mode(enum.Enum):
    OPEN_SESSION = 1,
    INVOKE_COMMAND = 2,
    CLOSES_ESSION = 3

  def __init__(self, ta, log_level=logging.INFO):
    self.log = logging.getLogger('[TaFuzzer]')
    self.log.setLevel(log_level)
    self._ta = ta

    self._param_actions = {
        utee_args.OpteeUteeParamType.NONE: self._setup_none_param,
        utee_args.OpteeUteeParamType.VALUE_INPUT: self._setup_int_param,
        utee_args.OpteeUteeParamType.VALUE_OUTPUT: self._setup_int_param,
        utee_args.OpteeUteeParamType.VALUE_INOUT: self._setup_int_param,
        utee_args.OpteeUteeParamType.MEMREF_INPUT: self._setup_buffer_param,
        utee_args.OpteeUteeParamType.MEMREF_OUTPUT: self._setup_buffer_param,
        utee_args.OpteeUteeParamType.MEMREF_INOUT: self._setup_buffer_param,
    }

  def _setup_int_param(self, param, data):
    sz = struct.calcsize(self.PARAM_INT_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    a, b = struct.unpack(self.PARAM_INT_FMT, data[:sz])
    param.a = a
    param.b = b
    return sz

  def _setup_buffer_param(self, param, data):
    sz = struct.calcsize(self.PARAM_BUFFER_FMT)
    if len(data) < sz:
      data += b'\x00' * (sz - len(data))
    size = struct.unpack(self.PARAM_BUFFER_FMT, data[:sz])[0]
    param.size = size & 0xFFFFF
    param.data = data[sz:param.size + sz]
    return len(param.data) + sz

  def _setup_none_param(self, param, data):
    del param, data  # unused in this function
    return 0

  def init(self, mode):
    """Starts AFL forkserver.

    After this call all commands will be executed for each *child*

    Args:
      mode: fuzzing mode as defined in TaFuzzer.Mode.

    Returns:
      True, if returns from child process.

    Raises:
      Error exception in case of unknown or unsupported mode.
    """

    if mode != self.Mode.INVOKE_COMMAND:
      raise error.Error('Sorry, but mode != InvokeCommand is not '
                        'supported for now!')

    self.mode = mode
    # optee session before starting forkserver for performance
    if mode == self.Mode.INVOKE_COMMAND:
      self._ta.open_session(self.SESSION_ID, [])

    return self._ta.forkserver_start()

  def run(self, data: bytes):
    """Runs Ta emulation.

    Args:
      data: bytes of input which will be parsed and converted to input for
            Ta.

    Returns:
      return status as defined in OpteeErrorCode

    Raises:
      Error exception in case of unexpected error.
    """

    sz = struct.calcsize(self.HDR_FMT)

    if len(data) < sz:
      data += b'\x00' * (sz - len(data))

    cmd, types = struct.unpack(self.HDR_FMT, data[:sz])

    offset = sz
    param_list = []
    for i in range(self.OPTEE_NUM_PARAMS):
      try:
        t = utee_args.OpteeUteeParamType((types >> (i * 4)) & 0x7)
      except ValueError:
        continue
      param = utee_args.OpteeUteeParam.get_type(t)()
      off = self._param_actions[t](param, data[offset:])
      offset += off
      param_list.append(param)

    ret = optee_error.OpteeErrorCode.SUCCESS
    try:
      ret, _ = self._ta.invoke_command(self.SESSION_ID, cmd, param_list)
      self._ta.close_session(self.SESSION_ID)
    except ta_error.TaPanicError as e:
      logging.error(e.message)
      ret = e.ret
    except ta_error.TaExit as e:
      logging.error(e.message)
      ret = e.ret

    return ret

  def stop(self):
    self._ta.exit(0)
