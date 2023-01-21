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
