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
import tsmok.emu.optee.ta_arm64 as ta_arm64
import tsmok.optee.crypto as crypto_module
import tsmok.optee.image_elf_ta as image_elf_ta
import tsmok.optee.optee as optee
import tsmok.optee.rpmb_simple as rpmb_simple
import tsmok.optee.ta.hello_world as ta_hello_world


def signal_handler(emu, sig, frame):
  del sig, frame  # not used
  print('You pressed Ctrl+C!')
  emu.exit(0)


# Run ROM
def main(args):
  """Runs TA emulation.

  Args:
    args: Arguments from command line

  Returns:
    0, if no error, -1 otherwise
  """

  log_level = None
  log_fmt = '| %(funcName)32s:%(lineno)-4d| %(levelname)-16s| %(message)s'
  if not args.verbose:
    log_fmt = '| %(name)-32s| %(levelname)-16s| %(message)s'
    log_level = logging.ERROR
  elif args.verbose == 1:
    log_level = logging.INFO
  elif args.verbose == 2:
    log_level = logging.DEBUG
  else:
    log_level = const.LogLevelCustom.DEBUG_DISASM

  logging.basicConfig(format=log_fmt, level=logging.NOTSET)
  log = logging.getLogger('[MAIN]')
  log.setLevel(log_level)

  log.info('Run TA emulator')

  try:
    storage = rpmb_simple.StorageRpmbSimple(log_level=log_level)

    tee = optee.Optee(crypto_module=crypto_module.CryptoModule(),
                      log_level=log_level)
    tee.storage_add(storage)

    img = image_elf_ta.TaElfImage(args.ta)

    ta = ta_arm64.TaArm64Emu(tee, log_level=log_level)
    ta.load(img)

    signal.signal(signal.SIGINT, lambda s, f: signal_handler(ta, s, f))

    if args.coverage:
      cov = cov_drcov.DrCov(log_level=log_level)
      cov.add_module(img)
      collector = cov_collectors.BlockCollector(cov)
      ta.coverage_register(collector)

    hello_world = ta_hello_world.HelloWorldTa(ta)

    value = 10
    new_value = hello_world.Increment(value)
    if (value + 1) != new_value:
      raise error.Error('HelloWorld: value was not incremented!')

    new_value = hello_world.Decrement(new_value)
    if value != new_value:
      raise error.Error('HelloWorld: value was not decremented!')

    if args.coverage:
      collector.stop()
      args.coverage.write(cov.dump())

    return 0

  except error.Error as e:
    log.error(e)
    return -1


def parse_args():
  """Parses command line arguments."""

  ag = argparse.ArgumentParser(description='OPTEE TA Emulator')
  ag.add_argument('--verbose', '-v', action='count',
                  help='Increase output verbosity')
  ag.add_argument('--ta', '-t', type=argparse.FileType('rb'),
                  required=True, help='TA binary to run')
  ag.add_argument('--data', '-d', type=argparse.FileType('rb'),
                  required=False, help='binary for call')
  ag.add_argument('--coverage', '-c', type=argparse.FileType('wb'),
                  required=False, default=None,
                  help='coverage file')
  return ag.parse_args()


if __name__ == '__main__':
  sys.exit(main(parse_args()))
