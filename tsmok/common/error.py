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

"""Defines main exceptions used in code."""

import os
import signal
import sys
import traceback


def PrintException() -> str:
  _, exc_obj, tb = sys.exc_info()
  stack_summary = traceback.extract_tb(tb)
  stack_str = traceback.format_list(stack_summary)
  return f'Exception: {exc_obj}\nTraceback:\n{"".join(stack_str)}'


class Error(Exception):

  def __init__(self, message):
    Exception.__init__(self, message)
    self.message = message


class AbortError(Error):

  def __init__(self, message=''):
    Error.__init__(self, message)


class SegfaultError(Error):

  def __init__(self, message=''):
    Error.__init__(self, message)


class SigIllError(Error):

  def __init__(self, message=''):
    Error.__init__(self, message)


def ConvertErrorToCrash(exc):
  """Converts *Error exception to application crash with corresponding signal.

  This function should be called to indicate to AFL that a crash occurred
  during emulation.

  Args:
    exc: tsmok.common.error.*Error exception
  """
  if isinstance(exc, SegfaultError):
    os.kill(os.getpid(), signal.SIGSEGV)
  if isinstance(exc, SigIllError):
    # Invalid instruction - throw SIGILL
    os.kill(os.getpid(), signal.SIGILL)
  else:
    # Not sure what happened - throw SIGABRT
    os.kill(os.getpid(), signal.SIGABRT)
