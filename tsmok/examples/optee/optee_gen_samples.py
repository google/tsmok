"""Wrapper for AFL fuzzing a TA."""

import argparse
import logging
import os
import sys
import tsmok.optee.syscall_declarations as syscall_decl
import tsmok.optee.syscalls as optee_syscalls
import tsmok.optee.utee_args as utee_args


SAMPLE_BASE_NAME = 'sample-{}.bin'


def gen_ta_samples(dir_path):
  """Generate binary input samples for TA fuzzing.

  Args:
    dir_path: the directory path for sampels output.

  Returns:
    None

  Raises:
    None
  """

  sample_id = 0
  syscalls = syscall_decl.ta_syscall_types()

  open_session = syscalls[optee_syscalls.OpteeTaCall.OPEN_SESSION]
  invoke_command = syscalls[optee_syscalls.OpteeTaCall.INVOKE_COMMAND]

  out = bytes(open_session(1, []))
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1

  out += bytes(invoke_command(None, [utee_args.OpteeUteeParamValueInOut(1, 0)],
                              0))

  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1

  out = bytes(open_session(1, []))
  out += bytes(invoke_command(None, [utee_args.OpteeUteeParamValueInOut(1, 0)],
                              1))
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(out)
  sample_id += 1


def gen_tee_samples(dir_path):
  """Generate binary input samples for TEE fuzzing.

  Args:
    dir_path: the directory path for sampels output.

  Returns:
    None

  Raises:
    None
  """

  log = logging.getLogger('[MAIN]')

  sample_id = 0
  syscalls = syscall_decl.tee_syscall_types()

  call = syscalls[optee_syscalls.OpteeSysCall.RETURN](0)
  log.info('Sample[%d] - syscalls: %s', sample_id, call)
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(bytes(call))
  sample_id += 1

  call = syscalls[optee_syscalls.OpteeSysCall.RETURN](1)
  log.info('Sample[%d] - syscalls: %s', sample_id, call)
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(bytes(call))
  sample_id += 1

  call = syscalls[optee_syscalls.OpteeSysCall.LOG](b'TestLogMessage\n',
                                                   len(b'TestLogMessage\n'))
  log.info('Sample[%d] - syscalls: %s', sample_id, call)
  with open(dir_path + SAMPLE_BASE_NAME.format(sample_id), 'bw') as f:
    f.write(bytes(call))
  sample_id += 1


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

  gen_func_map[args.mode](args.sample_dir)

  return ret


gen_func_map = {
    'ta': gen_ta_samples,
    'tee': gen_tee_samples,
    }


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
  parser.add_argument('--sample-dir', '-o', action=WritableDir,
                      required=True, default=None,
                      help='Sample output dir')
  parser.add_argument('--mode', '-m',
                      choices=gen_func_map.keys(),
                      default='api',
                      help='Select what example has to be run: API or Syscall')

  return parser.parse_args()


if __name__ == '__main__':
  sys.exit(run(parse_args()))
