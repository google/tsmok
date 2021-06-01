"""Wrapper for AFL fuzzing a TA."""

import argparse
import logging
import os
import sys

import tsmok.common.syscall_decl.parser.general as sys_parser


SAMPLE_BASE_NAME = 'input-{:03d}.bin'


# Run ROM
def run(args):
  """Runs Splitter.

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

  log.info('Input data Splitter.')

  data = args.file.read()
  data = data.split(sys_parser.Syscall.CALLDELIM)
  idx = 0

  for d in data:
    if not d:
      continue
    with open(args.out + SAMPLE_BASE_NAME.format(idx), 'bw') as f:
      f.write(sys_parser.Syscall.CALLDELIM + d)
    idx += 1

  return 0


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

  parser = argparse.ArgumentParser(description='Input Data Splitter')
  parser.add_argument('--verbose', '-v', action='count',
                      help='Increase output verbosity')
  parser.add_argument('--file', '-f', type=argparse.FileType('rb'),
                      required=True, default=None,
                      help='The input file')
  parser.add_argument('--out', '-o', action=WritableDir,
                      required=True, default=None,
                      help='Output dir')

  return parser.parse_args()


if __name__ == '__main__':
  sys.exit(run(parse_args()))
