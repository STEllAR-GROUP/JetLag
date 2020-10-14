from __future__ import absolute_import

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

from collections import defaultdict
from typing import DefaultDict
import networkx as nx

from phyfleaux.core.profiling import Profiler
class Expression:
    def __init__(self, expression, parent) -> None:
        self.profile = Profiler()
        self.expression = expression
        self.parent = parent


class ExpressionTree(nx.DiGraph):
    def __init__(self: Expression) -> None:
        root = 
        self.root = nx.add_node()


if __name__ == "__main__":
    import pytiramisu
    G = expression_tree = ExpressionTree()
    G.add_nodes_from([
        (4, {
            "color": "red"
        }),
        (5, {
            "color": "green"
        }),
    ])
    # expression_tree = ExpressionTree()
    # expression_tree.add_node((lambda: print('hello world'), {'c': 'g'}))
    print(G[4])
    # print(expression_tree.nodes)
    print(pytiramisu.__dir__())