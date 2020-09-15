from __future__ import absolute_import

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import numpy
import time

from phyfleaux.physl.directives import polyhedral
from phyfleaux.physl.plugins import numpy as numphy

# test sizes
small = [2, 4, 8, 16]
medium = [16, 32, 64, 128]
large = [128, 256, 512, 1024]
xlarge = [1024, 2048, 4096, 8192]


# run tests
def run(func, inputs=small):
    print(f"Running {func} with {inputs}")
    for args in inputs:
        print(f'{args}:')
        start = time.time()
        func(args)
        stop = time.time()
        print(stop - start)


@polyhedral
def matmul_naive_polyhedral(N: int, dtype=int) -> numphy.ndarray:
    """Apply polyhedral transformations to :fn:`matmul_naive`."""

    A = numphy.ones((N, N), dtype=int)
    B = numphy.ones((N, N), dtype=int)
    C = numphy.zeros((N, N), dtype=int)

    for i in range(N):
        for j in range(N):
            for k in range(N):
                C[i][j] = C[i][j] + A[i][k] * B[k][j]
    return C


run(matmul_naive_polyhedral)
