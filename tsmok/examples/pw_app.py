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

"""Test application for TA emulation."""

import argparse
import logging
import signal
import sys

import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.coverage.collectors as cov_collectors
import tsmok.coverage.drcov as cov_drcov
import tsmok.emu.pw_arm as pw_arm
import tsmok.hw.stm32f429.devices as stm_devices
import tsmok.hw.stm32f429.regs as stm_regs
import tsmok.pigweed.image_elf_pw as image_elf_pw


def signal_handler(emu, sig, frame):
  del sig, frame  # not used
  print('You pressed Ctrl+C!')
  emu.exit(0)


# Run ROM
def main(args):
  """Runs PW emulation.

  Args:
    args: Arguments from command line

  Returns:
    0, if no error, -1 otherwise
  """
  log_level = None
  if not args.verbose:
    log_fmt = '| %(levelname)-7s| %(message)s'
    log_level = logging.ERROR
  elif args.verbose == 1:
    log_fmt = '| %(levelname)-7s| %(message)s'
    log_level = logging.INFO
  elif args.verbose == 2:
    log_fmt = '| %(funcName)32s:%(lineno)-4d| %(levelname)-16s| %(message)s'
    log_level = logging.DEBUG
  else:
    log_fmt = '| %(funcName)32s:%(lineno)-4d| %(levelname)-16s| %(message)s'
    log_level = const.LogLevelCustom.DEBUG_DISASM

  logging.basicConfig(format=log_fmt, level=logging.NOTSET)
  log = logging.getLogger('[MAIN]')
  log.setLevel(log_level)

  log.info('Run PIGWEED emulator')

  try:
    img = image_elf_pw.PwElfImage(args.binary)
    pw = pw_arm.PwArmV7mEmu(log_level=log_level)
    pw.load(img)

    pw.driver_add(stm_devices.Ahb1(log_level=log_level))
    pw.driver_add(stm_devices.Gpio(stm_regs.GpioBaseReg.GPIOA,
                                   log_level=log_level))
    pw.driver_add(stm_devices.Uart(stm_regs.UartBaseReg.USART1,
                                   log_level=log_level))

    if args.coverage:
      cov = cov_drcov.DrCov(log_level=logging.DEBUG)
      cov.add_module(pw.image.name, pw.image.text_start,
                     pw.image.text_end)
      collector = cov_collectors.BlockCollector(cov)
      pw.coverage_register(collector)

    signal.signal(signal.SIGINT, lambda s, f: signal_handler(pw, s, f))

    pw.run()

    if args.coverage:
      collector.stop()
      args.coverage.write(cov.dump())
    return 0

  except error.Error as e:
    log.error(e)
    return -1


def parse_args():
  """Parses command line arguments."""

  ag = argparse.ArgumentParser(description='PIGWEED Emulator')
  ag.add_argument('--verbose', '-v', action='count',
                  help='Increase output verbosity')
  ag.add_argument('--binary', '-b', type=argparse.FileType('rb'),
                  required=True, help='PW binary to run')
  ag.add_argument('--coverage', '-c', type=argparse.FileType('wb'),
                  required=False, default=None, help='coverage file')

  return ag.parse_args()


if __name__ == '__main__':
  sys.exit(main(parse_args()))
