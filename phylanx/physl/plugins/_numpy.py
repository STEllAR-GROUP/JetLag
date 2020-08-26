from __future__ import absolute_import

__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

from copy import deepcopy
from numpy import *

SymbolTable = dict()

_array = deepcopy(array)
_ndarray = deepcopy(ndarray)

# ##############################################################################
# Start: overload numpy methods
# ##############################################################################


def array(data_object, dtype=None, copy=True, order='K', subok=False, ndmin=0):

    np_array = _array(data_object,
                      dtype=None,
                      copy=True,
                      order='K',
                      subok=False,
                      ndmin=0)
    SymbolTable[str(np_array.data)] = {'size': len(np_array)}
    return np_array


def ndarray(data_object,
            dtype=None,
            copy=True,
            order='K',
            subok=False,
            ndmin=0):

    np_ndarray = _ndarray(data_object,
                          dtype=None,
                          copy=True,
                          order='K',
                          subok=False,
                          ndmin=0)
    SymbolTable[str(np_ndarray.data)] = {'size': len(np_ndarray)}
    return np_ndarray


# ##############################################################################
# End: overload numpy methods
# ##############################################################################
