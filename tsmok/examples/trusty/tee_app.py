"""Test application for Trusty emulator."""

import argparse
import logging
import os
import signal
import sys

import tsmok.atf.atf_trusty as atf
import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.common.memory as memory
import tsmok.coverage.collectors as cov_collectors
import tsmok.coverage.drcov as cov_drcov
import tsmok.emu.trusty.tee_arm64 as trusty_arm64
import tsmok.hw.devices.gic as hw_gic
import tsmok.hw.devices.rpmb as hw_rpmb
import tsmok.trusty.image_elf_tee as trusty_image
import tsmok.trusty.ipc as trusty_ipc
import tsmok.trusty.ta.avb as trusty_avb
import tsmok.trusty.ta.rpmb_proxy as trusty_rpmb


LOAD_ADDR = 0xc0000000
RAM_SIZE = 0x409000
EMMC_CID = b'0123456789ABCDEF'
SHM_ADDR = 0xd0000000
SHM_PAGES = 64
CLIENT_ID = 0xaa
IPC_CHAN_SIZE = 4096
AVB_PERM_ATTR_SIZE = 1052

RPMB_AUTH_KEY = (b'\xea\xdf\x64\x44\xea\x65\x5d\x1c'
                 b'\x87\x27\xd4\x20\x71\x0d\x53\x42'
                 b'\xdd\x73\xa3\x38\x63\xe1\xd7\x94'
                 b'\xc3\x72\xa6\xea\xe0\x64\x64\xe6')


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
  rpmb = hw_rpmb.RpmbDevice(EMMC_CID, key=RPMB_AUTH_KEY)
  if args.rpmb:
    args.rpmb.seek(0)
    data = args.rpmb.read()
    if data:
      rpmb.load(data)

  gic = hw_gic.GicV3(log_level=log_level)
  tee = trusty_arm64.TrustyArm64Emu(atf_os, log_level=log_level)
  tee.driver_add(gic)

  # MAP RAM
  tee.map_memory(LOAD_ADDR, RAM_SIZE, memory.MemAccessPermissions.RW)

  # MAP SHARED Memory for IPC
  tee.shared_memory_add(SHM_ADDR, SHM_PAGES)

  signal.signal(signal.SIGINT, lambda s, f: signal_handler(tee, s, f))

  try:
    img = trusty_image.TrustyElfImage(args.file, LOAD_ADDR)
    tee.load(img)

    if args.coverage:
      cov = cov_drcov.DrCov(log_level=logging.DEBUG)
      cov.add_module(tee.image)
      collector = cov_collectors.BlockCollector(cov)
      tee.coverage_register(collector)

    tee.init(RAM_SIZE)

    mgr = trusty_ipc.IpcManager(tee, CLIENT_ID, IPC_CHAN_SIZE)

    rpmb_proxy = trusty_rpmb.RpmbProxy(mgr.get_client('RPMB'), rpmb)  # pylint: disable=unused-variable
    avb = trusty_avb.Avb(mgr.get_client('AVB'))

    ver = avb.get_version()
    log.info('AVB: Version %d', ver)

    state = avb.lock_state_read()
    log.info('AVB: Current Lock State %d', state)

    new_state = state ^ 1

    avb.lock_state_write(new_state)

    state = avb.lock_state_read()
    log.info('AVB: New Lock State %d', state)
    if state != new_state:
      log.error('AVB: Lock State writing does not work!')

    value = avb.rollback_index_read(1)
    log.info('AVB: Current RB Index for 1: %d', value)

    new_value = 0xd

    avb.rollback_index_write(1, new_value)

    value = avb.rollback_index_read(1)
    log.info('AVB: New RB Index for 1: %d', value)
    if value != new_value:
      log.error('AVB: RB Index writing does not work!')

    perm_attr = os.urandom(AVB_PERM_ATTR_SIZE)

    check_perm_attr_write = True
    try:
      avb.perm_attr_write(perm_attr)
    except error.Error as e:
      log.warning('PERM Attr is already written')
      check_perm_attr_write = False
    data = avb.perm_attr_read()
    log.info('AVB: Permanent Attributes size %d', len(data))

    if check_perm_attr_write and data != perm_attr:
      log.error('AVB: Perm Attr writing does not work!')

    mgr.shutdown()

    if args.rpmb_update and args.rpmb:
      args.rpmb.seek(0)
      args.rpmb.write(rpmb.dump())

    if args.coverage:
      collector.stop()
      args.coverage.write(cov.dump())
    return 0

  except error.Error as e:
    log.error(e)
    return -1


def parse_args():
  """Parses command line arguments."""

  ag = argparse.ArgumentParser(description='Trusty Emulator')

  ag.add_argument('--verbose', '-v', action='count',
                  help='Increase output verbosity')

  ag.add_argument('--file', '-f', type=argparse.FileType('rb'),
                  required=True, help='Trusty binary to run')

  ag.add_argument('--rpmb', '-r', type=argparse.FileType('a+'),
                  required=False,
                  help='RPMB state to load.')

  ag.add_argument('--rpmb_update', '-u', action='store_const',
                  required=False, const=True, default=False,
                  help='RPMB state to load.')

  ag.add_argument('--coverage', '-c', type=argparse.FileType('wb'),
                  required=False, default=None, help='coverage file')

  return ag.parse_args()


if __name__ == '__main__':
  sys.exit(main(parse_args()))
