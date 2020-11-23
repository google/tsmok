# TSMOK
**T**ester and **S**ecurity researcher fir**M**ware emulat**O**r **K**it - **TSMOK** (pronounce [[(t)smok]](https://en.wikipedia.org/wiki/Slavic_dragon)) is a engine to emulate firmware for testing and research purpose. **TSMOK** is based on [Unicorn](https://www.unicorn-engine.org/) engine.

# Current status
* **TSMOK** is ready for testing/fuzzing OPTEE TAs.
* Python OPTEE instance currently support 30 of 80 syscalls (enough to run the most of TAs)
* OPTEE TEE emulation [IN PROGRESS].
* basic support for Pigweed project

# Features
* Modular structure.
* Supports OPTEE TA, TEE Arm and Pigweed ARM ELF binaries.
* Contains simple python OPTEE instance (written on python) to support TA's external calls.
* Python OPTEE instance has simple implementation of RPMB storage.
* **TSMOK** tracks:
	* execution flow (instruction, function and syscalls)
	* memory access
	* syscall access
	* Mem/Reg control and examination
* Coverage support.
* Fuzzing.

# Area of usage
* Testing: tests(unit/functional) with about any complexity can be written.
* Security research
* Fuzzing

# Installation
#### Install module 
`python3 setup.py install`
### Install only dependencies
`pip3 install -r requirements.txt`
### Fuzzing
[AFLPlusPlus](https://github.com/AFLplusplus) is requeired for fuzzing. **AFLPlusPlus** installation instruction can be found on its page.

### Set pylint commit hook
This is needed to do code style check before every commit.
#####Install git dependency
`pip3 install git-pylint-commit-hook`
#####Install hook
<code>
cat > .git/hooks/pre-commit <\<EOD <br/>#!/bin/sh <br> git-pylint-commit-hook <br>EOD
</code>

# Examples
### Pigweed binary run
`python3 -m tsmok.example.pw_app -b <path/to/binary>`

### Run local unittests
`python3 -m tests.test_rpmb_simple`

# Contributers
Dmitry Yatsushkevich <dmitryya@google.com>

# TODO
* OPTEE emulation [IN PROGRESS]
* Finish implementation of all syscall in Python OPTEE instance.
* ATF emulation
* GDB Remote Protocol