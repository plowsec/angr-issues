import logging
import claripy
from angr import ExplorationTechnique
from angr.exploration_techniques.common import condition_to_lambda
from angr.state_plugins import resource_event

from helpers.log import logger
import networkx as nx


class CFGFollower(ExplorationTechnique):

    def _handle_cycles(self):
        """
        nodes leading back to an ok_block are included
        this allows to handle loops in the CFG: for instance a basic block that checks the loop counter
        has 2 successors. if loop body is not included in ok_blocks, the successor that leads back to the
        check block will be discarded and the exit conditions will never be met.
        """

        def dfs(node, path, visited):
            logger.debug(f"Visiting node: {node.addr:#x}")
            if node.addr in self.ok_blocks and len(path) > 0:
                for n in path:
                    self.ok_blocks.add(n.addr)
                    logger.debug(f"Adding node to ok_blocks from path: {n.addr:#x}")
                return True

            if node.addr in visited:
                return False

            visited.add(node.addr)
            path.append(node)
            for succ in node.successors:
                dfs(succ, path, visited)

            path.pop()
            return False

        for addr in list(self.ok_blocks):
            nodes = self.cfg.model.get_all_nodes(addr)
            for node in nodes:
                dfs(node, [], set())


    # Modify the __init__ method to call _include_loop_subgraphs
    def __init__(
            self, find=None, avoid=None, find_stash="found", avoid_stash="avoid", cfg=None, num_find=1
    ):
        super().__init__()
        self.find, static_find = condition_to_lambda(find)
        self.avoid, static_avoid = condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.cfg = cfg
        self.ok_blocks = set()
        self.num_find = num_find

        # even if avoid or find addresses are not statically known, stop on those that we do know
        self._extra_stop_points = (static_find or set()) | (static_avoid or set())
        self._unknown_stop_points = static_find is None or static_avoid is None

        if self.cfg is not None:
            avoid = static_avoid or set()

            # we need the find addresses to be determined statically
            if not static_find:
                logger.error("You must provide at least one numeric 'find' address if you provide a CFG.")
                logger.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            for a in avoid:
                if cfg.model.get_any_node(a) is None:
                    logger.warning("'Avoid' address %#x not present in CFG...", a)
                    return

            # not a queue but a stack... it's just a worklist!
            stack = []
            for f in static_find:
                nodes = cfg.model.get_all_nodes(f)
                if len(nodes) == 0:
                    logger.warning("'Find' address %#x not present in CFG...", f)
                else:
                    stack.extend(nodes)

            seen_nodes = set()
            while len(stack) > 0:
                n = stack.pop()
                if id(n) in seen_nodes:
                    continue
                if n.addr in avoid:
                    continue
                self.ok_blocks.add(n.addr)
                logger.debug(f"Adding node to ok_blocks: {n.addr:#x}")
                seen_nodes.add(id(n))
                stack.extend(n.predecessors)

            # Ensure all nodes leading to ok_blocks are included
            self._handle_cycles()

            if len(self.ok_blocks) == 0:
                logger.error("No addresses could be validated by the provided CFG!")
                logger.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            logger.warning("Please be sure that the CFG you have passed in is complete.")
            logger.warning("Providing an incomplete CFG can cause viable paths to be discarded!")


    def setup(self, simgr):
        if self.find_stash not in simgr.stashes:
            simgr.stashes[self.find_stash] = []
        if self.avoid_stash not in simgr.stashes:
            simgr.stashes[self.avoid_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        base_extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

    # make it more natural to deal with the intended dataflow
    def filter(self, simgr, state, **kwargs):
        stash = self._filter_inner(state)
        if stash is None:
            return simgr.filter(state, **kwargs)
        return stash

    def _filter_inner(self, state):
        try:
            findable = self.find(state)
            if findable and (findable is True or state.addr in findable):
                return self.find_stash

            avoidable = self.avoid(state)
            if avoidable and (avoidable is True or state.addr in avoidable):
                return self.avoid_stash

        except claripy.errors.ClaripySolverInterruptError as e:
            resource_event(state, e)
            return "interrupted"

        if self.cfg is not None and self.cfg.model.get_any_node(state.addr) is not None:
            if state.addr not in self.ok_blocks:

                return self.avoid_stash

        return None

    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find

    def successors(self, simgr, state, **kwargs):
        """
        Override the successors method to prioritize DFS exploration.
        """
        successors = simgr.successors(state, **kwargs)
        if self.cfg is not None:
            # Prioritize successors that are in the ok_blocks set
            successors.flat_successors.sort(key=lambda s: s.addr not in self.ok_blocks)
        return successors