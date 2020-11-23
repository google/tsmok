"""round_up function implementations."""


def round_up(number, multiple):
  num = number + (multiple - 1)
  return num - (num % multiple)
