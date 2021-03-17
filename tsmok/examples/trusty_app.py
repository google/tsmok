"""Test application for OPTEE emulator."""

import argparse
import logging
import signal
import sys

import tsmok.atf.atf_trusty as atf
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.emu.trusty_arm64 as trusty_arm64
import tsmok.hw.devices.gic as hw_gic
import tsmok.hw.devices.rpmb as hw_rpmb
import tsmok.trusty.image_elf_tee as trusty_image

LOAD_ADDR = 0xc0000000
RAM_SIZE = 0x409000
EMMC_CID = b'0123456789ABCDEF'


def signal_handler(emu, sig, frame):
  del sig, frame  # not used
  print('You pressed Ctrl+C!')
  emu.exit(0)


# Run ROM
def main(args):
  """Runs TRUSTY emulation.

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

  log.info('Run TRUSTY emulator')

  atf_os = atf.AtfTrusty(log_level=log_level)
  rpmb = hw_rpmb.RpmbDevice(EMMC_CID)
  if args.rpmb:
    rpmb.load(args.rpmb.read())

  gic = hw_gic.GicV3(log_level=log_level)
  tee = trusty_arm64.TrustyArm64Emu(atf_os, log_level=log_level)
  tee.driver_add(gic)

  # MAP RAM
  tee.map_memory(LOAD_ADDR, RAM_SIZE, memory.MemAccessPermissions.RW)

  signal.signal(signal.SIGINT, lambda s, f: signal_handler(tee, s, f))

  try:
    img = trusty_image.TrustyElfImage(args.file, LOAD_ADDR)
    tee.load(img)
    tee.driver_add(rpmb)

    tee.init(RAM_SIZE)

    if args.rpmb_update and args.rpmb:
      args.rpmb.seek(0)
      args.rpmb.write(rpmb.dump())

  except error.Error as e:
    log.error(e)


def parse_args():
  """Parses command line arguments."""

  ag = argparse.ArgumentParser(description='OPTEE Emulator')

  ag.add_argument('--verbose', '-v', action='count',
                  help='Increase output verbosity')

  ag.add_argument('--file', '-f', type=argparse.FileType('rb'),
                  required=True, help='Trusty binary to run')

  ag.add_argument('--rpmb', '-r', type=argparse.FileType('r+'),
                  required=False,
                  help='RPMB state to load.')

  ag.add_argument('--rpmb_update', '-u', action='store_const',
                  required=False, const=True, default=False,
                  help='RPMB state to load.')

  return ag.parse_args()


if __name__ == '__main__':
  sys.exit(main(parse_args()))
