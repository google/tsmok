"""Wrapper for AFL fuzzing a TA."""

import argparse
import logging
import os
import sys

import tsmok.common.error as error
import tsmok.common.syscall_decl.parser.general as sys_parser
import tsmok.optee.syscall_parser as ta_parser
import tsmok.optee.syscalls as optee_syscalls

SAMPLE_BASE_NAME = 'sample-{}.bin'


# Run ROM
def run(args):
  """Runs Parser.

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

  try:
    if args.sample_dir:
      for _, _, filenames in os.walk(args.sample_dir):
        for file in filenames:
          log.info('Parse sample file %s ...', file)
          with open(args.sample_dir + '/' + file, 'rb') as f:
            data = f.read()
            for out in parse_data(syscalls, data):
              log.info(out)
    elif args.sample_file:
      data = args.sample_file.read()
      for out in parse_data(syscalls, data):
        log.info(out)
  except error.Error as e:
    log.error(e.message)

  return ret


def parse_data(syscalls, data):
  """Parse data.

  Args:
    syscalls: list with known syscall definitions
    data: raw binary data:

  Yields:
    Syscall object, initialized by parsed data.
  """

  args_data = data.split(sys_parser.Syscall.CALLDELIM)
  for adata in args_data:
    if not adata:
      continue
    nr = sys_parser.Syscall.parse_call_number(adata)
    try:
      syscall = syscalls[nr]
      call = syscall.create(adata)
      yield call
    except (KeyError, TypeError, IndexError):
      continue


class ReadableDir(argparse.Action):
  """argparse action to check that a dir is readable."""

  def __call__(self, parser, namespace, values, option_string=None):
    prospective_dir = values
    if not os.path.isdir(prospective_dir):
      raise argparse.ArgumentTypeError(f'ReadableDir:{prospective_dir} is '
                                       'not a valid path')
    if os.access(prospective_dir, os.R_OK):
      setattr(namespace, self.dest, prospective_dir)
    else:
      raise argparse.ArgumentTypeError(f'ReadableDir:{prospective_dir} is '
                                       'not a readable dir')


def parse_args():
  """Parses command line arguments."""

  parser = argparse.ArgumentParser(description='TA Sample generator')
  parser.add_argument('--verbose', '-v', action='count',
                      help='Increase output verbosity')
  parser.add_argument('--syscall-desc', '-s', type=argparse.FileType('r'),
                      required=True, default=None,
                      help='Syscall description file')
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument('--sample-dir', '-o', action=ReadableDir,
                     required=False, default=None,
                     help='The dir with samples')
  group.add_argument('--sample-file', '-f', type=argparse.FileType('rb'),
                     required=False, default=None,
                     help='The sample file')

  return parser.parse_args()


if __name__ == '__main__':
  sys.exit(run(parse_args()))
