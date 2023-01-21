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

"""Definition of tsmok module."""

import setuptools

with open('README.md', 'r') as fh:
  long_description = fh.read()

setuptools.setup(
    name='tsmok',
    version='0.0.1',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    scripts=['scripts/drcov_convertor'],
    test_suite='tests',
    install_requires=[
        'capstone>=4.0.2', 'coverage>=5.3', 'portion>=2.1.3',
        'sortedcontainers>=2.2.2', 'unicorn>=1.0.2', 'pyelftools>=0.27'
    ],
)
