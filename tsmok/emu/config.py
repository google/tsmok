"""Configuration for Arm emulator."""

# WORKAROUND: use unicornafl module only for fuzzing because it is
# not as stable as upstream unicorn module
AFL_SUPPORT = False
