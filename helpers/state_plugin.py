
from angr.state_plugins.plugin import SimStatePlugin
from copy import deepcopy

from helpers.log import logger
from typing import Dict, List, Tuple


class HeapState:
    def __init__(self):
        self.allocations: Dict[int, int] = {}  # addr -> size
        self.freed_regions: List[Tuple[int, int]] = []  # (addr, size)



class SimStateDeepGlobals(SimStatePlugin):
    """Based on angr's original globals state plugin, only difference is this one deep copies"""

    def __init__(self, backer=None):
        super(SimStateDeepGlobals, self).__init__()
        try:
            self._backer = deepcopy(backer) if backer is not None else {}
        except RecursionError:
            logger.warning("Failed to deep copy, using shallow instead")
            self._backer = backer if backer is not None else {}

        self.memory_allocs = 0
        self.heap_state = HeapState()

    def set_state(self, state):
        pass

    def merge(
            self, others, merge_conditions, common_ancestor=None
    ):  # pylint: disable=unused-argument
        for other in others:
            for k in other.keys():
                if k not in self:
                    self[k] = other[k]

        return True

    def widen(self, others):  # pylint: disable=unused-argument
        logger.warning("Widening is unimplemented for globals")
        return False

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt=None):
        return self._backer.get(k, alt)

    def pop(self, k, alt=None):
        return self._backer.pop(k, alt)

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateDeepGlobals(dict(self._backer))


def __print_history(state):
    summary = False
    if len(list(state.history.parents)) > 10:
        summary = True
    history = list(state.history.parents)
    history_length = len(history)
    print("\t\thistory [%s]:" % (history_length))
    for index, state in enumerate(history):
        if (index < 3 and summary):
            print("\t\t\t%s" % (state))
        if (index == history_length - 5):
            print("\t\t\t...")
        if (index > history_length - 5):
            print("\t\t\t%s" % (state))
