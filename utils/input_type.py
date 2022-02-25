import enum


class InputType(enum.Enum):
    STDIN = 0
    ARGS = 1
    REMOTE = 2