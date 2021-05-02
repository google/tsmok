"""Defines TA specific exceptions."""

import tsmok.optee.error as optee_error


class TaPanicError(Exception):

  def __init__(self, code, message):
    Exception.__init__(self, message)
    self.code = code
    self.ret = optee_error.OpteeErrorCode.ERROR_TARGET_DEAD
    self.message = message


class TaExit(Exception):  # pylint: disable=g-bad-exception-name

  def __init__(self, ret, message):
    Exception.__init__(self)
    self.ret = ret
    self.message = message
