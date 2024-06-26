import angr
from angr.exploration_techniques import ExplorationTechnique
from helpers.log import logger


class LeapFrogger(ExplorationTechnique):
    def __init__(self, bb_addresses):
        super().__init__()
        self.bb_addresses = bb_addresses

    def setup(self, simgr):
        simgr.stashes['found'] = []
        simgr.stashes['potential'] = []
        simgr.stashes['avoid'] = []
        for state in simgr.active:
            state.globals['leapfrog_index'] = 0
        return simgr

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        new_active = []
        for state in simgr.stashes[stash]:
            current_index = state.globals.get('leapfrog_index', 0)
            if current_index < len(self.bb_addresses):
                if state.addr == self.bb_addresses[current_index]:
                    logger.info(f"Reached basic block {hex(state.addr)}")
                    state.globals['leapfrog_index'] = current_index + 1
                    if state.globals['leapfrog_index'] == len(self.bb_addresses):
                        logger.info("Reached all basic blocks")
                        simgr.stashes['found'].append(state)
                    else:
                        new_active.append(state)
                else:
                    simgr.stashes['potential'].append(state)
            else:
                simgr.stashes['potential'].append(state)

        simgr.stashes[stash] = new_active

        # If active is empty, try to continue from potential states
        if not simgr.stashes[stash] and simgr.stashes['potential']:
            new_state = simgr.stashes['potential'].pop(0)
            #new_state.globals['leapfrog_index'] = 0  # Reset the index when switching to a new potential path
            simgr.stashes[stash] = [new_state]

        return simgr

    def complete(self, simgr):
        return len(simgr.found) > 0 or (
            all(state.globals.get('leapfrog_index', 0) >= len(self.bb_addresses) for state in simgr.active)
            and not simgr.stashes['potential']
        )