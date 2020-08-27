__license__ = """ 
Copyright (c) 2020 R. Tohid

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""


class Distributed:
    def __init__(self, *nodes):
        self.nodes = self.add_node(nodes)

    def add_node(self, nodes):
        nodes_ = list()
        for node in nodes:
            nodes_.append(node)
        return nodes_


class CPU:
    def __init__(self, num_threads=1, num_sockets=1, vectorized=False):
        self.num_threads = num_threads
        self.num_sockets = num_sockets
        self.vectorized = vectorized


class GPU:
    def __init__(self, num_threads, num_gpus):
        self.num_threads = num_threads
        self.num_gpus = num_gpus
        # sm: streaming multiprocessor
        self.sm = 16
