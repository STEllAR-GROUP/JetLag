from __future__ import absolute_import
from __future__ import annotations

__license__ = """ 
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

from typing import Union, Any
from types import FunctionType

from phyfleaux.core import Task
from phyfleaux.optimization.polyhedral import Polytope


def task(__task_arg=None, **kwargs):

    if callable(__task_arg):
        return Task(__task_arg)
    elif __task_arg is not None:
        raise TypeError(
            f"Function {task} expects {FunctionType} or {Task}"
        )
    else:
        return Task


def polyhedral(fn: Union[Task, FunctionType]) -> Polytope:
    """Attempts to detect SCoPs and apply polyhedral transformations.

    :arg fn: python function.

    Directs Phyfleaux to apply polyhedral transformations on affine iteration
    spaces in :func:`fn`.

    reads:
    -----
    https://polyhedral.info/

    https://en.wikipedia.org/wiki/Polytope_model
    https://en.wikipedia.org/wiki/Affine_space
    """

    task_ = task(fn)

    return Polytope(task_)
