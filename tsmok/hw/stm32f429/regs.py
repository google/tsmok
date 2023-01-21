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

"""stm32f429 registers."""

import enum


AHB1_BASE = 0x40020000
APB2_BASE = 0x40010000
APB1_BASE = 0x40000000


class RccReg(enum.IntEnum):
  RCC_BASE = AHB1_BASE + 0x3800
  AHB1ENR = RCC_BASE + 0x30
  AHB3ENR = RCC_BASE + 0x38
  APB2ENR = RCC_BASE + 0x44


class GpioBaseReg(enum.IntEnum):
  """Base addresses for GPIO blocks."""

  GPIOA = AHB1_BASE + 0x0000
  GPIOB = AHB1_BASE + 0x0400
  GPIOC = AHB1_BASE + 0x0800
  GPIOD = AHB1_BASE + 0x0c00
  GPIOE = AHB1_BASE + 0x1000
  GPIOF = AHB1_BASE + 0x1400
  GPIOG = AHB1_BASE + 0x1800
  GPIOH = AHB1_BASE + 0x1c00
  GPIOI = AHB1_BASE + 0x2000
  GPIOJ = AHB1_BASE + 0x2400
  GPIOK = AHB1_BASE + 0x2800


class GpioOffReg(enum.IntEnum):
  """GPIO offsets inside specific block."""

  MODE = 0x0
  OUTPUT_TYPE = 0x4
  OUTPUT_SPEED = 0x8
  PULL_UP_DOWN = 0x0c
  INPUT_DATA = 0x10
  OUTPUT_DATA = 0x14
  BIT_SET = 0x18
  CONF_LOCK = 0x1C
  ALT_FUNC_LOW = 0x20
  ALT_FUNC_HIGH = 0x24


class UartBaseReg(enum.IntEnum):
  USART2 = APB1_BASE + 0x4400
  USART3 = APB1_BASE + 0x4800
  UART4 = APB1_BASE + 0x4c00
  UART5 = APB1_BASE + 0x5000
  UART7 = APB1_BASE + 0x7800
  UART8 = APB1_BASE + 0x7C00
  USART1 = APB2_BASE + 0x1000
  USART6 = APB2_BASE + 0x1400


class UartOffReg(enum.IntEnum):
  STATUS = 0x00
  DATA = 0x04
  BAUD_RATE = 0x08
  CONTROL_1 = 0x0c
  CONTROL_2 = 0x10
  CONTROL_3 = 0x14
  GUARD_TIME_AND_PRESCALE = 0x18


