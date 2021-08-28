"""Wrapper for AFL fuzzing a TA."""

import argparse
import logging
import signal
import sys

import tsmok.common.const as const
import tsmok.common.error as error
import tsmok.coverage.collectors as cov_collectors
import tsmok.coverage.drcov as cov_drcov
import tsmok.emu.optee.ta_arm64 as ta_arm64
import tsmok.fuzzing.sys_fuzzer as fuzz
import tsmok.optee.crypto as crypto_module
import tsmok.optee.fuzzing.ta_fuzz as ta_fuzz
import tsmok.optee.image_elf_ta as image_elf_ta
import tsmok.optee.optee
import tsmok.optee.rpmb_simple as rpmb_simple
import tsmok.optee.syscall_declarations as syscall_decl
import tsmok.optee.syscalls as optee_syscalls


def sigint_handler(fuzzer, signum, frame):
  del signum, frame  # unused
  fuzzer.stop()


class TaExampleFuzzOps(ta_fuzz.TaFuzzingOps):
  """Ops for TA fuzzing."""

  def __init__(self):
    ta_fuzz.TaFuzzingOps.__init__(self)

    # limit cmd only to 0 and 1 for invoke_command
    self._nr_arg_handler[optee_syscalls.OpteeTaCall.INVOKE_COMMAND]['cmd'] = \
        self._invoke_cmd_filter

  def _invoke_cmd_filter(self, value):
    return value % 2


def syscall_filter(syscalls):
  filtered_syscalls = dict()
  filtered_syscalls[optee_syscalls.OpteeTaCall.INVOKE_COMMAND] = \
      syscalls[optee_syscalls.OpteeTaCall.INVOKE_COMMAND]
  return filtered_syscalls


# Run ROM
def run(args):
  """Runs TA emulation.

  Args:
    args: Arguments from command line

  Returns:
    0, if no error, non 0 otherwise
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

  storage = rpmb_simple.StorageRpmbSimple(log_level=log_level)
  tee = tsmok.optee.optee.Optee(crypto_module=crypto_module.CryptoModule(),
                                log_level=log_level)
  tee.storage_add(storage)

  ta = ta_arm64.TaArm64Emu(tee, log_level=log_level)
  img = image_elf_ta.TaElfImage(args.binary)
  ta.load(img)

  syscalls = syscall_decl.ta_syscall_types()
  # interested in fuzzing only INVOKE_COMMAND,
  # thus filter out other syscalls.
  syscalls = syscall_filter(syscalls)

  sid = 1
  ta.open_session(sid, [])

  ta_ops = ta_fuzz.TaExampleFuzzOps(ta)

  log.info('Run TA fuzzer')
  fuzzer = fuzz.SysFuzzer(ta_ops.get_ctx(), syscalls,
                          features=fuzz.Feature.RESOURCE_SMART,
                          log_level=log_level)
  signal.signal(signal.SIGINT, lambda s, f: sigint_handler(fuzzer, s, f))
  fuzzer.resource_add_value('cmd', sid)

  if args.coverage:
    cov = cov_drcov.DrCov(log_level=log_level)
    cov.add_module(img)
    collector = cov_collectors.BlockCollector(cov)
    ta.coverage_register(collector)

  try:
    is_child = fuzzer.init()
  except error.Error as e:
    logging.root.error(e.message)
    return -1

  if is_child:  # if child process
    # disable logging to improve performance
    logging.root.setLevel(logging.CRITICAL)

  with open(args.input_file, 'rb') as f:
    data = f.read()

  try:
    ret = fuzzer.run(data)
  except error.Error as e:
    logging.error(e.message)
    error.ConvertErrorToCrash(e)

  if args.coverage and not is_child:
    collector.stop()
    args.coverage.write(cov.dump())

  return ret


def parse_args():
  """Parses command line arguments."""

  parser = argparse.ArgumentParser(description='TA emulator')
  parser.add_argument('--verbose', '-v', action='count',
                      help='Increase output verbosity')
  parser.add_argument('--coverage', '-c', type=argparse.FileType('wb'),
                      required=False, default=None,
                      help='coverage file')
  parser.add_argument('binary', type=argparse.FileType('rb'),
                      help='binary path')
  parser.add_argument('input_file', type=str,
                      help='Path to the file containing the mutated input')

  return parser.parse_args()


if __name__ == '__main__':
  sys.exit(run(parse_args()))
