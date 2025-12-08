from __future__ import annotations

import errno
import os
import sys
from functools import wraps
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def catch_sigpipe(func: Callable) -> Callable:
    """Catches ``KeyboardInterrupt`` and ``BrokenPipeError`` (``OSError 22`` on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Aborted!", file=sys.stderr)
            return 1
        except OSError as e:
            # Only catch BrokenPipeError or OSError 22
            if e.errno in (errno.EPIPE, errno.EINVAL):
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return 1
            # Raise other exceptions
            raise

    return wrapper
