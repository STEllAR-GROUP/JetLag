from __future__ import absolute_import
from __future__ import annotations

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import ast
from typing import Callable, Union, Any

from phyfleaux.core.task import Task
from phyfleaux.plugins.tiramisu import Buffer, Call, Computation, Expr, Function
from phyfleaux.plugins.tiramisu import Return, Var


class Polytope(ast.NodeVisitor):
    def __init__(self, task_: Task) -> None:
        """Representation of functions in affine spaces.

        :arg task_: :class:task:`Task` object

        related resources:
        ------------------
        https://polyhedral.info/

        https://en.wikipedia.org/wiki/Polytope_model
        https://en.wikipedia.org/wiki/Affine_space
        """

        self.task = task_
        self.isl_build()

    def isl_build(self):
        fn_body = self.task.py_ast.body[0]

        self.isl_tree = self.visit_(fn_body)
        self.isl_tree.build()
        # self.isl_tree.gencode()

    def isl_gencode(self):
        pass

    def visit_(self, node: Callable, throw_exception: bool = False):
        """By default :func:`ast.visit` returns None if the virtual class is not
        implemented by the user. This may cause error later on.
        :func:`Polytope.visit_` calls the default visit, and if `None` is
        returned throws an exception.
        """
        returned = self.visit(node)
        if returned is None:
            raise NotImplementedError(
                f"Transformation rule for {node} is not implemented.")
        else:
            return returned

    def __call__(self, *args, **kwargs):
        # self.isl_tree(*args, **kwargs)
        self.task(*args, **kwargs)

    def visit_Add(self, node: ast.Add) -> str:
        return '__Add__'

    def visit_Assign(self, node: ast.Assign) -> Computation:
        id = hash(node)
        target = node.targets
        value = node.value

        rhs = self.visit_(value)

        if 1 < (len(target)):
            raise NotImplementedError(
                "Multi-target assignments are not yet supported.")
        lhs = self.visit_(target[0])
        s = Computation(lhs, rhs, id)

        return s

    def visit_Attribute(self, node: ast.Attribute) -> None:
        return node.attr

    def visit_BinOp(self, node: ast.BinOp) -> Call:
        fn_name = self.visit_(node.op)

        lhs = self.visit_(node.left)
        rhs = self.visit_(node.right)
        args = [lhs, rhs]

        fn = Call(fn_name, hash(node), args)

        return fn

    def visit_Call(self, node: ast.Call) -> Call:
        if isinstance(node.func, str):
            fn_name = node.func
        else:
            fn_name = self.visit_(node.func)

        if isinstance(node.args, list):
            args = [self.visit_(arg) for arg in node.args]
        else:
            args = self.visit_(node.args)

        if not isinstance(fn_name, str):
            raise TypeError(f"Expected {str}, received {fn_name}")

        fn = Call(fn_name, args, self.task.id, self.task.dtype)

        for attr in node.keywords:
            value = self.visit_(attr.value)
            setattr(fn, attr.arg, value)

        return fn

    def visit_Constant(self, node: ast.Constant) -> Union[int, str]:
        return node.value

    def visit_Expr(self, node: ast.Expr) -> Expr:
        return Expr(self.visit_(node.value))

    def visit_For(self, node: ast.For) -> Var:
        loop = Var(hash(node.target))
        loop.iterator = self.visit_(node.target)

        if isinstance(node.iter, ast.Call) and 'range' == node.iter.func.id:
            bounds = self.visit_(node.iter)
            iter_space = bounds.args

            if not isinstance(iter_space, type(None)):
                if 1 == len(iter_space):
                    loop.set_bounds(lower=0, upper=iter_space[0])
                if 2 == len(iter_space):
                    loop.set_bounds(lower=iter_space[0], upper=iter_space[1])
                if 3 == len(iter_space):
                    loop.set_bounds(lower=iter_space[0],
                                    upper=iter_space[1],
                                    stride=iter_space[2])

        if isinstance(node.iter, ast.List):
            raise TypeError(":class:`ast.List` might not be an affine space.")

        for statement in node.body:
            statement_isl = self.visit_(statement)
            if not isinstance(statement_isl, str):
                loop.body[hash((statement))] = statement_isl

        return loop

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Function:

        # Return.reset()
        parameters = [arg for arg in node.args.args]
        dtype = self.task.dtype
        fn = Function(node.name, self.task, self.task.id, parameters, dtype)

        for statement in node.body:
            if not isinstance(statement, str):
                if isinstance(statement, ast.Expr):
                    if isinstance(statement.value, ast.Constant):
                        continue
            else:
                continue
            visited_statement = self.visit_(statement)
            if not isinstance(visited_statement, str):
                if isinstance(visited_statement, Return):
                    fn.add_return(visited_statement)
                fn.add_statement(visited_statement, fn.id)

        return fn

    def visit_Index(self, node: ast.Index) -> Any:
        return self.visit_(node.value)

    def visit_Mult(self, node: ast.Mult) -> str:
        return '__Mult__'

    def visit_Name(self, node: ast.Name) -> str:
        return node.id

    def visit_Return(self, node):
        return_ = Return(self.visit_(node.value), hash(node))
        Return.add(return_)

        return return_

    def visit_Slice(self, node: ast.Slice) -> Any:
        lower = self.visit_(node.lower)
        upper = self.visit_(node.upper)
        step = self.visit_(node.step)

        return (lower, upper, step)

    def visit_Subscript(self, node: ast.Subscript) -> tuple:
        def _NestedSubscript(node):
            value_slice = self.visit_(node.value)
            slice_ = [self.visit_(node.slice)]
            if isinstance(node.value, ast.Subscript):
                value_slice = _NestedSubscript(node.value)

            if isinstance(value_slice, list):
                value = value_slice + slice_
            else:
                value = [value_slice] + slice_

            return value

        slice_ = [self.visit_(node.slice)]
        if isinstance(node.value, ast.Subscript):
            value_slice = _NestedSubscript(node.value)
        else:
            value_slice = self.visit_(node.value)

        if isinstance(value_slice, list):
            value = value_slice + slice_
        else:
            value = [value_slice] + slice_
        print(value)
        return value

    def visit_Tuple(self, node: ast.Tuple) -> None:
        return tuple([self.visit_(expr) for expr in node.elts])
