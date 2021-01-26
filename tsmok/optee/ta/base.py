"""OPTEE TA base."""

import abc
from typing import List
import tsmok.optee.const as optee_const
import tsmok.optee.types as optee_types


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
      params: List[optee_types.OpteeTaParam]
      ) -> (optee_const.OpteeErrorCode, List[optee_types.OpteeTaParam]):
    raise NotImplementedError()

  @abc.abstractmethod
  def invoke_command(
      self, sid: int, cmd: int,
      params: List[optee_types.OpteeTaParam]
      ) -> (optee_const.OpteeErrorCode, List[optee_types.OpteeTaParam]):
    raise NotImplementedError()

  @abc.abstractmethod
  def close_session(self, sid: int) -> (optee_const.OpteeErrorCode):
    raise NotImplementedError()
