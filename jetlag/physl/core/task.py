from __future__ import absolute_import
from __future__ import annotations

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import ast
import inspect

from collections import OrderedDict
from typing import Union
from types import FunctionType


class Cost:
    def __init__(self):
        pass


class Task:
    def __init__(self,
                 fn: Union[FunctionType, Task],
                 cost: FunctionType = None) -> None:
        if isinstance(fn, FunctionType):

            # Function
            self.fn = fn
            self.id = self.fn.__hash__()
            self.dtype = None

            self.py_code = fn.__code__
            self.py_ast = ast.parse((inspect.getsource(fn)))

            # Function Signature
            self.signature = inspect.signature(fn)
            self.args_spec = inspect.getfullargspec(fn)

            # Function Source
            self.src = inspect.getsource(fn)
            self.src_file, self.start_lineno = inspect.findsource(self.fn)
            self.src_file = ''.join(map(str, self.src_file))
            self.src_file_dir = '/'.join(inspect.getfile(fn).split('/')[:-1])
            self.src_file_name = inspect.getfile(fn).split('/')[-1]
            self.cost = OrderedDict()
            self.new_cost(cost)

        else:  # isinstance(fn, Task)
            self = fn
            self.new_cost(cost)

        self.called = 0

    def new_cost(self, cost, reset: bool = False):
        if reset:
            self.cost = OrderedDict()

        id = hash(cost)
        if self.cost.get(id):
            self.cost[id].append((cost, id))
        else:
            self.cost[id] = [(cost, id)]

        return

    def __call__(self, *args, **kwargs):
        # inspect.signature(fn).bind()
        self.called += 1
        return self.fn(*args, **kwargs)

    def __hash__(self):
        return self.id
