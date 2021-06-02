"""OPTEE TA base."""

import abc
from typing import List
import tsmok.optee.error as optee_error
import tsmok.optee.utee_args as utee_args


class Ta(abc.ABC):
  """Base interface for OPTEE TA."""

  def __init__(self, name, uuid):
    self.uuid = uuid
    self.name = name

  def get_name(self) -> str:
    return self.name

  def get_uuid(self) -> str:
    return self.uuid

  @abc.abstractmethod
  def open_session(
      self, sid: int,
      params: List[utee_args.OpteeUteeParam]
      ) -> (optee_error.OpteeErrorCode, List[utee_args.OpteeUteeParam]):
    raise NotImplementedError()

  @abc.abstractmethod
  def invoke_command(
      self, sid: int, cmd: int,
      params: List[utee_args.OpteeUteeParam]
      ) -> (optee_error.OpteeErrorCode, List[utee_args.OpteeUteeParam]):
    raise NotImplementedError()

  @abc.abstractmethod
  def close_session(self, sid: int) -> (optee_error.OpteeErrorCode):
    raise NotImplementedError()
