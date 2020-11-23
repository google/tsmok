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
