# TSMOK
**T**ester and **S**ecurity researcher fir**M**ware emulat**O**r **K**it - **TSMOK** (pronounce [[(t)smok]](https://en.wikipedia.org/wiki/Slavic_dragon)) is a tool to emulate firmware for testing and research purpose. **TSMOK** is based on [Unicorn](https://www.unicorn-engine.org/) engine.

# Features
* Modular structure.
* Supports OPTEE OS, OPTEE TA, Trusty OS and Pigweed ARM ELF binaries.
* Fake ATF, OPTEE and HW components implementations.
* Python OPTEE instance has simple implementation of RPMB storage.
* FF-A support
* MMU support
* **TSMOK** tracks:
	* execution flow (instruction, function and syscalls)
	* memory access
	* syscall access
	* Mem/Reg control and examination
* Coverage support (gcov, lcov) base on disasm and ELF DWARF
* AFL support for fuzzing(AFL has instrumentation for Unicorn engine).
* OPTEE TA fuzzing support
* Extensibility: easy to add new fake HW component support or new tracking/analyzing feature.

# Area of usage
* Testing: tests(unit/functional) with about any complexity can be written.
* Security research
* Fuzzing

# Installation
### Install custom UnicornAFL
`git clone https://github.com/dmitryya/unicornafl.git -b tee-dev`

`cd unicornafl/bindings/python`

`sudo python3 setup.py install`

### Install dependencies
`pip3 install -r requirements.txt`
### Install TSMOK
`python3 setup.py install`
### Fuzzing
[AFLPlusPlus](https://github.com/AFLplusplus) is requeired for fuzzing. **AFLPlusPlus** installation instruction can be found on its page.

### Set pylint commit hook
This is needed to do code style check before every commit.

#####Install git dependency

`pip3 install git-pylint-commit-hook`

#####Install hook

`cat > .git/hooks/pre-commit << EOD`

`#!/bin/sh`

`git-pylint-commit-hook`

`EOD`

# Examples
### Pigweed binary run
`python3 -m tsmok.example.pw_app -b <path/to/binary> -v`

### Trusty OS binary run
`python3 -m tsmok.examples.trusty.tee_app -f images/examp
les/trusty/trusty-os.elf -v`

### OPTEE TA binary run
`python -m tsmok.examples.optee.ta_arm64_app -t images/examples/optee/8aaaf200-2450-11e4-abe2-0002a5d5c51b.elf -v`

### OPTEE TA binary fuzzing
`afl-fuzz -U -m none -i images/examples/optee/ta-fuzz-samples/ -o <path/to/result> -M fuzzer01 -- python3 -m  tsmok.examples.optee.ta_arm64_fuzz_app images/examples/optee/8aaaf200-2450-11e4-abe2-0002a5d5c51b-with-crash.elf @@`

### Run local unittests
`python3 -m tests.test_rpmb_simple`

# Contributers
Dmitry Yatsushkevich <dmitryya@google.com>

# TODO
* Fuzzing for OPTEE, Trusty(?)
* Individual Trusty TA support (?)
* GDB remote client support
* Performance optimization
* Coverage support improvements
* Add RPMB FS support

