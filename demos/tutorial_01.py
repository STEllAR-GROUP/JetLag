from __future__ import absolute_import

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import numpy
import time

from jetlag.physl.directives import polyhedral
from jetlag.physl.plugins import numpy as numphy

# test sizes
sizes = [2, 4], 8, 16, 32, 64, 128]


# run tests
def run(func, sizes):
    for N in sizes:
        start = time.time()
        print(func(N))
        stop = time.time()
        print(stop - start)


@polyhedral
def fill_matrix(N: int, dtype=int) -> numphy.ndarray:
    """Apply polyhedral transformations to :fn:`matmul_naive`."""

    A = numphy.zeros((N, N), dtype=int)

    for i in range(N):
        for j in range(N):
            A[i][j] = i * N + j
    return A


run(fill_matrix, sizes)
