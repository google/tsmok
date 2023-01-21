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
