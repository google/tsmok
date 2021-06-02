"""OPTEE VX TA implementation."""

import enum
import logging
import uuid
import tsmok.common.error as error
import tsmok.common.ta_error as ta_error
import tsmok.optee.error as optee_error
import tsmok.optee.ta.base as ta_base
import tsmok.optee.utee_args as utee_args


class HelloWorldTa:
  """HelloWorld TA wrapper on top of TA emulator to provide native ta's API."""

  class Cmd(enum.IntEnum):
    """HelloWorld TA commands."""
    INCREMENT = 0x00
    DECREMENT = 0x01

  UUID = uuid.UUID(int=0x8aaaf200245011e4abe20002a5d5c51b)

  def __init__(self, ta: ta_base.Ta, log_level=logging.ERROR):
    if self.UUID != ta.uuid:
      raise error.Error('Unsupported TA(uuid: {str(ta.uuid)}')

    self.log = logging.getLogger('[PROVISION TA]')
    self.log.setLevel(log_level)
    self.ta = ta
    self.session = None

  def SessionOpen(self) -> None:
    """Open Session."""

    if self.session:
      return

    sid = 1
    ret, _ = self.ta.open_session(sid, [])
    if ret != optee_error.OpteeErrorCode.SUCCESS:
      raise ta_error.TaExit(ret, 'TA Open session exited with return code '
                            f'{str(ret)}')

    self.session = sid

  def SessionClose(self) -> None:
    if not self.session:
      return

    sid = self.session
    self.session = None

    ret = self.ta.close_session(sid)
    if ret != optee_error.OpteeErrorCode.SUCCESS:
      raise ta_error.TaExit(ret, 'TA Close session exited with return code '
                            f'{str(ret)}')

  def Increment(self, value) -> int:
    """Increment the value.

    Args:
      value: value to increment

    Returns:
      Incremented value

    Raises:
      ta_error.TaExit: if failed with error
    """

    if not self.session:
      self.SessionOpen()

    cmd = int(self.Cmd.INCREMENT)
    params = [
        utee_args.OpteeUteeParamValueInOut(),
    ]
    params[0].a = value
    ret, params = self.ta.invoke_command(self.session, cmd, params)
    if ret != optee_error.OpteeErrorCode.SUCCESS:
      raise ta_error.TaExit(ret, 'Write Efuse exited with return '
                            f'code {str(ret)}')

    return params[0].a

  def Decrement(self, value) -> int:
    """Decrement the value.

    Args:
      value: value to increment

    Returns:
      Decremented value

    Raises:
      ta_error.TaExit: if failed with error
    """

    if not self.session:
      self.SessionOpen()

    cmd = int(self.Cmd.DECREMENT)
    params = [
        utee_args.OpteeUteeParamValueInOut(),
    ]
    params[0].a = value
    ret, params = self.ta.invoke_command(self.session, cmd, params)
    if ret != optee_error.OpteeErrorCode.SUCCESS:
      raise ta_error.TaExit(ret, 'Write Efuse exited with return '
                            f'code {str(ret)}')

    return params[0].a
