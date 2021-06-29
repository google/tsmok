"""Wrapper for AFL fuzzing a TA."""

import argparse
import logging
import os
import sys

import tsmok.fuzzing.parser.optee_ta as ta_parser
import tsmok.optee.syscalls as optee_syscalls
import tsmok.optee.utee_args as utee_args

SAMPLE_BASE_NAME = 'sample-{}.bin'


# Run ROM
def run(args):
  """Runs Sample Generator.

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
  else:
    log_level = logging.DEBUG

  logging.basicConfig(format=log_fmt, level=logging.NOTSET)
  log = logging.getLogger('[MAIN]')
  log.setLevel(log_level)
  ret = 0

  syscalls = {}

  for line in args.syscall_desc.read().splitlines():
    call = ta_parser.parse(line)
    try:
      nr = optee_syscalls.OpteeTaCall(call.NR)
    except ValueError:
      log.error('Unknown TA call number: %d', call.NR)
      return -1
    syscalls[nr] = call

  gen_samples(args.sample_dir, syscalls)

  return ret


def gen_samples(dir_path, syscalls):
  """Generate binary input samples for TA fuzzing.

  Args:
    dir_path: the directory path for sampels output.
    syscalls: list on know syscalls.

  Returns:
    None

  Raises:
    None
  """

  sample_id = 0

  open_session = syscalls[optee_syscalls.OpteeTaCall.OPEN_SESSION]
  invoke_command = syscalls[optee_syscalls.OpteeTaCall.INVOKE_COMMAND]

  out = bytes(open_session(1, []))
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1

  out += bytes(invoke_command(1, [utee_args.OpteeUteeParamValueInOut(1, 0)], 0))

  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1

  out = bytes(open_session(1, []))
  out += bytes(invoke_command(1, [utee_args.OpteeUteeParamValueInOut(1, 0)], 1))
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1


class WritableDir(argparse.Action):
  """argparse action to check that a dir is writable."""

  def __call__(self, parser, namespace, values, option_string=None):
    prospective_dir = values
    if not os.path.isdir(prospective_dir):
      raise argparse.ArgumentTypeError(f'WritableDir:{prospective_dir} is '
                                       'not a valid path')
    if os.access(prospective_dir, os.W_OK):
      setattr(namespace, self.dest, prospective_dir)
    else:
      raise argparse.ArgumentTypeError(f'WritableDir:{prospective_dir} is '
                                       'not a readable dir')


def parse_args():
  """Parses command line arguments."""

  parser = argparse.ArgumentParser(description='TA Sample generator')
  parser.add_argument('--verbose', '-v', action='count',
                      help='Increase output verbosity')
  parser.add_argument('--syscall-desc', '-s', type=argparse.FileType('r'),
                      required=True, default=None,
                      help='Syscall description file')
  parser.add_argument('--sample-dir', '-o', action=WritableDir,
                      required=True, default=None,
                      help='Sample output dir')

  return parser.parse_args()


if __name__ == '__main__':
  sys.exit(run(parse_args()))
