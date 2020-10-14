from __future__ import absolute_import
from __future__ import annotations

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import ast

from collections import OrderedDict, defaultdict
from typing import Any, List, Union

from pytiramisu import buffer, computation, constant, expr, function
from pytiramisu import init_physl, input, var
from pytiramisu import uint32_expr
from jetlag.physl.core.task import Task


class Load:
    pass


class Store:
    pass


class Del:
    pass


class Index:
    def __init__(self, name: str, index: List) -> None:
        self.name = name
        self.index = index

    def variables(self):
        vars = list()
        for entry in self.index:
            if not isinstance(entry, int):
                vars.append(entry)
        return vars


# Tiramisu objects
# ---------------------------------------------------------------------------- #
class Buffer:
    def __init__(self,
                 name: str,
                 id: int,
                 indices: List,
                 context: Union[ast.Load, ast.Store] = None) -> None:
        """Represents memory buffers."""

        self.id = id
        self.name = name
        self.indices = OrderedDict()

        self._read_write = {'loads': OrderedDict(), 'stores': OrderedDict()}
        if context:
            self.set_context(name, id, context)

        self.isl = None

    def build(self):
        raise NotImplementedError

    def dimension(self):
        return len(self.indices)

    def loads(self):
        return self._read_write['loads']

    def get_context(self, name: str, id: int) -> Union[Load, Store]:
        return self._read_write[name][id]

    def set_context(self, name: str, id: int,
                    context: Union[ast.Load, ast.Store]) -> None:

        context: Union[ast.Load, ast.Store]
        if isinstance(context, ast.Load):
            self._read_write['loads'][name] = id
        else:
            self._read_write['stores'][name] = id

    def stores(self):
        return self.get_context()['stores']


class Call:
    stack = OrderedDict()

    def __init__(self, fn_name: str, args: Any, id: int, dtype=None):
        self.name = fn_name
        self.id = id
        self.dtype = dtype
        self.args = args
        self.isl = None

        call_stack = Call.stack
        if call_stack.get(fn_name):
            call_stack[fn_name].append(self)
        else:
            call_stack[fn_name] = [self]

    def build(self):
        print(self.args)
        # raise NotImplementedError


class Computation:
    statements = OrderedDict()

    def __init__(self, lhs=None, rhs=None, id=None):
        """A computation has an expression (class:`Expression`) and 
        iteration domain defined using an :class:`Iterator`."""
        self._lhs = lhs
        self._rhs = rhs
        self.id = id
        self.iter_domain = None
        self.name = 'S' + str(len(Computation.statements))
        self.isl = None
        Computation.statements[self.name] = self

    @property
    def lhs(self):
        return self._lhs

    @lhs.setter
    def lhs(self, targets):
        self._lhs = targets

    @property
    def rhs(self):
        return self._rhs

    @rhs.setter
    def rhs(self, expr):
        self._rhs = expr

    def build(self):
        rhs_ = Computation.statements[self.name].rhs
        lhs_ = Computation.statements[self.name].lhs
        if hasattr(rhs_, 'build'): rhs_.build()
        if hasattr(lhs_, 'build'): lhs_.build()


class Constant:
    def __init__(self):
        """Designed to represent constants that are supposed to be declared at
        the beginning of a Tiramisu function. This can be used only to declare
        constant scalars."""
        self.isl = None


class Expr:
    tree = OrderedDict()

    def __init__(self, value: ast.Expr) -> None:
        """Represnets expressions, e.g., 4, 4 + 4, 4 * i, A[i, j], ..."""
        self.id = hash(value)
        self.value = value
        self.add_to_tree()

    def add_to_tree(self) -> None:
        Expr.tree[self.id] = self

    def build(self):
        raise NotImplementedError


class Function:
    defined = OrderedDict()

    def __init__(self,
                 name: str,
                 task: Task,
                 id: int,
                 params: Any,
                 dtype=None) -> None:
        """Equivalent to a function in C; composed of multiple computations and
        possibly Vars."""

        self.name = name
        self.task = task
        self.dtype = dtype

        self.body = OrderedDict()

        self.num_returns = 0
        self.returns = OrderedDict()

        if task:
            self.define()

    def add_statement(self, statement: Any, id: int):
        self.body[statement.id] = statement

    def add_return(self, return_val):
        self.num_returns += 1
        self.returns[self.num_returns] = return_val

    def build(self):
        # for arg in self.-+
        init_physl(self.name)
        body_ = self.body
        for value in body_.values():
            value.build()
            self.add_statement(value, value.id)
        for return_ in self.returns:
            if hasattr(return_, 'build'): return_.build()

    def define(self):
        defined_ = Function.defined.get(self.name)

        self.id = self.task.id
        args = self.task.args_spec.args

        for arg in args:
            print(arg)

        if defined_:
            Function.defined[self.name].append(self.id)
        else:
            Function.defined[self.name] = [self.id]


class Input:
    def __init__(self):
        """An input can represent a buffer or a scalar"""
        pass


class Return:
    returns = OrderedDict()

    def __init__(self, value, id) -> None:
        self.id = id
        self.value = value

    def build(self):
        print(self.id, self.value)

    @classmethod
    def add(cls, return_):
        Return.returns[return_.id] = return_

    def num_return(self):
        return len(Return.returns.keys())

    @classmethod
    def reset(cls):
        Return.returns = OrderedDict()


class Var:
    iters = OrderedDict()

    def __init__(self, id: int, iterator=None):
        """Defines the range of the loop around the computation (its iteration
        domain). When used to declare a buffer it defines the buffer size, and
        when used with an input it defines the input size."""

        self.id = id
        self.iterator = iterator
        self.bounds = {'lower': None, 'upper': None, 'stride': None}
        self.body = OrderedDict()

    def set_bounds(self, lower=None, upper=None, stride=1):
        if lower:
            self.bounds['lower'] = lower
        else:
            self.bounds['lower'] = 0

        self.bounds['upper'] = upper
        self.bounds['stride'] = stride

    def build(self):
        for statement in self.body.values():

            if hasattr(statement, 'build'):
                self.body[self.id] = statement.build()
