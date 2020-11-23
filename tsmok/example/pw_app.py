"""Test application for TA emulation."""

import argparse
import logging
import sys

import tsmok.common.error as error
import tsmok.coverage.collectors as cov_collectors
import tsmok.coverage.drcov as cov_drcov
import tsmok.emu.arm as arm
import tsmok.emu.pw_arm as pw_arm
import tsmok.hw.stm32f429.devices as stm_devices
import tsmok.hw.stm32f429.regs as stm_regs
import tsmok.pigweed.image_elf_pw as image_elf_pw


# Run ROM
def run(cmd_args):
  """Runs PW emulation.

  Args:
    cmd_args: Arguments from command line

  Returns:
    0, if no error, -1 otherwise
  """
  log = logging.getLogger('[MAIN]')

  log.info('Run PW emulator')

  try:

    img = image_elf_pw.PwElfImage(cmd_args.binary)

    if not cmd_args.verbose:
      log_level = logging.ERROR
    elif cmd_args.verbose == 1:
      log_level = logging.INFO
    elif cmd_args.verbose == 2:
      log_level = logging.DEBUG
    else:
      log_level = arm.ArmEmu.LOG_DEBUG_DISASM

    pw = pw_arm.PwArmEmu(log_level=log_level)
    pw.load(img)

    pw.driver_add(stm_devices.Ahb1(log_level=log_level))
    pw.driver_add(stm_devices.Gpio(stm_regs.GpioBaseReg.GPIOA,
                                   log_level=log_level))
    pw.driver_add(stm_devices.Uart(stm_regs.UartBaseReg.USART1,
                                   log_level=log_level))

    if cmd_args.coverage:
      cov = cov_drcov.DrCov(log_level=logging.DEBUG)
      cov.add_module(pw.image.name, pw.image.text_start, pw.image.text_end,
                     pw.image.sha256)
      collector = cov_collectors.BlockCollector(cov)
      pw.coverage_register(collector)

    pw.run()

    if cmd_args.coverage:
      collector.stop()
      cmd_args.coverage.write(cov.dump())

  except error.Error as e:
    log.error(e)


def parse_args():
  """Parses command line arguments."""

  ag = argparse.ArgumentParser(description='PIGWEED Emulator')
  ag.add_argument(
      '--verbose', '-v', action='count', help='Increase output verbosity')
  ag.add_argument(
      '--binary', '-b',
      type=argparse.FileType('rb'),
      required=True,
      help='PW binary to run')
  ag.add_argument(
      '--coverage', '-c',
      type=argparse.FileType('wb'),
      required=False, default=None,
      help='coverage file')

  return ag.parse_args()


def main():
  args = parse_args()
  if not args.verbose:
    logging.basicConfig(
        format='| %(name)-32s| %(levelname)-16s| %(message)s',
        level=logging.NOTSET)
    logging.root.setLevel(logging.INFO)
  else:
    logging.basicConfig(
        format='| %(funcName)32s:%(lineno)-4d| %(levelname)-16s| %(message)s',
        level=logging.NOTSET)
    logging.root.setLevel(logging.DEBUG)

  run(args)


if __name__ == '__main__':
  sys.exit(main())
