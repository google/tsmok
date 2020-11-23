"""Defines main exceptions used in code."""

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
