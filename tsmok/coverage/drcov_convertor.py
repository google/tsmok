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

"""Defines DRCOV convertors for by disassembling ELF binary."""

import logging
import os.path

import tsmok.coverage.base as coverage


class GcovConvertor(coverage.CoverageConvertorBase):
  """Implementation for gcov convertor."""

  def __init__(self, cov: coverage.CoverageRepresentationBase,
               log_level=logging.ERROR, name='GcovConvertor'):
    coverage.CoverageConvertorBase.__init__(self, name)
    self.coverage = cov

  def dump(self, output: str):
    for source in self.coverage.sources:
      src = f'{source.get_full_path()}'
      gcov = f'{os.path.abspath(output)}/{source.name}.gcov'

      out = f'        -:        0:Source:{src}\n'
      out += '        -:        0:Graph:\n'
      out += '        -:        0:Data:\n'
      out += f'        -:        0:Runs:{self.coverage.runs}\n'

      for func in sorted(source.funcs.values(), key=lambda x: x.lineno):
        return_percent = func.returned_percent()
        lines_percent = func.lines_coverage_percentages()
        out += f'function {func.name} called {func.called} returned '
        if return_percent is not None:
          out += f'{return_percent:6.2f}% '
        else:
          out += 'UNK '
        out += f'lines executed {lines_percent:6.2f}%\n'
        for line in func.lines:
          if not line.count:
            out += '    #####:'
          else:
            out += f'{line.count:9d}:'

          out += f'  {line.lineno:8d}:\t' + str(line) + '\n'

      self.log.info(f'Writing GCOV into {gcov}')
      with open(gcov, 'w') as f:
        f.write(out)

      if source.data:
        self.log.info(f'Writing SOURCE into {src}')
        with open(f'{output}/{source.name}', 'w') as f:
          f.write(source.data)


class LcovConvertor(coverage.CoverageConvertorBase):
  """Converts drcov into lcov convertor."""

  def __init__(self, cov: coverage.CoverageRepresentationBase,
               log_level=logging.ERROR, name='LcovConvertor'):
    coverage.CoverageConvertorBase.__init__(self, name)
    self.coverage = cov

  def dump(self, output: str, hex_lines=False):
    info = f'{os.path.abspath(output)}/coverage.info'
    out = ''
    for source in self.coverage.sources:
      src = f'{source.get_full_path()}'

      out += 'TN\n'
      out += f'SF:{src}\n'

      for func in sorted(source.funcs.values(), key=lambda x: x.lineno):
        out += f'FN:{func.lineno},{func.name}\n'
        out += f'FNDA:{func.called},{func.name}\n'
        for line in sorted(func.lines, key=lambda x: x.lineno):
          out += f'DA:{line.lineno},{line.count}\n'
      out += 'end_of_record\n'

      if source.data:
        self.log.info(f'Writing SOURCE into {src}')
        with open(f'{output}/{source.name}', 'w') as f:
          f.write(source.data)

    self.log.info(f'Writing LCOV into {info}')
    with open(info, 'w') as f:
      f.write(out)


class BriefTxtConvertor(coverage.CoverageConvertorBase):
  """Convertor for simple text format from drcov."""

  def __init__(self, cov: coverage.CoverageRepresentationBase,
               log_level=logging.ERROR, name='TxtConvertor'):
    coverage.CoverageConvertorBase.__init__(self, name)
    self.coverage = cov

  def dump(self, output: str):
    txt = f'{os.path.abspath(output)}/coverage.txt'

    out = ''
    for source in self.coverage.sources:
      out += f'Source:{source.get_full_path()}\n'
      out += f'Runs:{self.coverage.runs}\n'

      report = []
      for func in source.funcs.values():
        return_percent = func.returned_percent()
        lines_percent = func.lines_coverage_percentages()
        report.append((func.name, func.called, return_percent, lines_percent))

      for item in sorted(report, key=lambda i: i[3], reverse=True):
        out += f'Function {item[0]:64s}: called {item[1]:8d}, returned '
        if return_percent is not None:
          out += f'{item[2]:6.2f}%, '
        else:
          out += 'UNK'
        out += f'lines executed {item[3]:6.2f}%\n'

    self.log.info(f'Writing TXT into {txt}')
    with open(txt, 'w') as f:
      f.write(out)

