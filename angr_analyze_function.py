import functools
import pickle
from typing import Dict, List, Tuple

import angr
import sys
import IPython
import logging
import uuid

import claripy

from exploration_techniques.CFGFollower import CFGFollower
from helpers.log import logger
from helpers import angr_introspection, state_plugin
from helpers import shared, checks
from targets.windows import hooks, utils, opcodes
from targets.generic import libc
from sanitizers import integer_overflow
from sanitizers import heap

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("angr.exploration_techniques").setLevel(logging.DEBUG)


def inspect_new_constraint(state):
    logger.debug(f'new constraint {state.inspect.added_constraints}')




def set_hooks(proj):
    proj.hook_symbol('__stdio_common_vfprintf', hooks.stdio_common_vfprintf())
    proj.hook_symbol('__acrt_iob_func', hooks.acrt_iob_func())
    proj.hook_symbol('printf', angr.procedures.libc.printf.printf())
    proj.hook_symbol('sprintf', angr.procedures.libc.sprintf.sprintf())
    proj.hook_symbol('fprintf', angr.procedures.libc.fprintf.fprintf())


def check_for_vulns(*args, **kwargs):
    sm = args[0]

    for state in sm.active:
        if state.loop_data.current_loop is not None and len(state.loop_data.current_loop) > 0:
            logger.debug(f'loop: {state.loop_data.current_loop}')

    integer_overflow.check_for_vulns(sm, shared.proj)
    """for state in sm.active:
        logger.debug(f'{state.addr} {state.regs.rip}')
        detect_overflow(state)
    """


def create_simgr(proj, addr_target):
    # Get control flow graph.
    #shared.cfg = angr_proj.analyses.CFGFast(normalize=True )
    shared.cfg = proj.analyses.CFGEmulated(fail_fast=True, normalize=True, keep_state=True)

    # Enumerate functions
    angr_introspection.angr_enum_functions(proj)
    shared.proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True, cfg=shared.cfg)

    # Set hooks
    set_hooks(proj)

    # Create a new state with the function arguments set up
    state = proj.factory.blank_state()

    # Manually create a symbolic buffer
    input_buf_len = state.solver.BVV(0x10, 64)  # Example length for InputBufLen
    input_buffer = state.solver.BVS('input_buffer', 0x10 * 8)  # Create a symbolic bitvector for the buffer

    # Allocate memory for the buffer and store the symbolic buffer in memory
    input_buffer_addr = state.solver.BVV(0x100000, 64)  # Example address to store the buffer
    state.memory.store(input_buffer_addr, input_buffer)

    shared.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(shared.proj.arch)

    # init_analysis(angr_proj)

    state = proj.factory.call_state(
        addr_target,
        input_buffer_addr,
        input_buf_len,
        cc=shared.mycc,
        prototype="void call_me(char *InputBuffer, int64_t InputBufLen);"
    )

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    """
    state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
    state.options.add(angr.options.LAZY_SOLVES)
    state.options.add(angr.options.SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS)
    state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
    state.options.add(angr.options.TRACK_CONSTRAINTS)
    state.options.add(angr.options.TRACK_TMP_ACTIONS)
    state.options.add(angr.options.SYMBOLIC_TEMPS)

    """

    state.inspect.b('call', when=angr.BP_BEFORE, action=angr_introspection.inspect_call)
    #state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    #state.inspect.b('address_concretization', when=angr.BP_AFTER, action=inspect_concretization)
    #state.inspect.b('mem_write', when=angr.BP_BEFORE, action=check_oob_write)

    state.register_plugin("deep", state_plugin.SimStateDeepGlobals())
    state.deep.memory_allocs = 0

    shared.state = state
    shared.simgr = proj.factory.simgr(state)
    shared.phase = 2

    logger.debug(shared.simgr.active[0].regs.rip)
    return shared.simgr


def exploration_done(symbolic_vars=None):
    s = shared.simgr
    logger.debug(f'active: {len(s.active)}')
    logger.debug(f'found: {len(s.found)}')
    logger.debug(f'avoid: {len(s.avoid)}')

    if len(s.avoid) > 0:
        # pretty print the avoid states
        for state in s.avoid[:5]:
            logger.debug(f'avoid state: {state}')
            angr_introspection.pretty_print_callstack(state)

    logger.debug(f'deadended: {len(s.deadended)}')
    logger.debug(f'errored: {len(s.errored)}')

    if len(s.errored) > 0:
        for state in s.errored[:5]:
            angr_introspection.show_errors(state)

    logger.debug(f'unsat: {len(s.unsat)}')
    logger.debug(f'uncons: {len(s.unconstrained)}')

    logger.debug("Done")
    if len(s.found) > 0:

        found = s.one_found
        logger.debug("Found state")
        logger.debug(f'found: {found}')
    else:
        logger.debug("No found state")





def analyze_old(angr_proj):
    addr_target = 0x0000000140001000
    create_simgr(angr_proj, addr_target)

    # shared.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=shared.args.bound))
    # shared.simgr.use_technique(angr.exploration_techniques.LengthLimiter(shared.args.length))
    # shared.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=shared.cfg, bound=50))

    # analyze_stack_vars()

    # 00000001400010D0 loop overflow
    # 0x000000014000109D simple overflow
    find_addresses = [0x1400014E5]

    checks.check_find_addresses(find_addresses)

    #shared.simgr.use_technique(CFGFollower(cfg=shared.cfg, find=find_addresses))

    shared.simgr.explore(
        find=find_addresses,
        # avoid=[0x00000001400010E0],
        step_func=check_for_vulns,
        cfg=shared.cfg
    )

    #shared.simgr.run()

    exploration_done()


def analyze(proj):
    shared.cfg = proj.analyses.CFGEmulated(fail_fast=True, normalize=True, keep_state=True)

    # Enumerate functions
    angr_introspection.angr_enum_functions(proj)
    shared.proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True, cfg=shared.cfg)
    run_heap_operations_addr = 0x1400011C0
    should_have_crashed_addr = 0x00000001400012DE
    count = claripy.BVS('count', 32)
    operations = claripy.BVS('operations', 32 * 3)  # Assuming a maximum of 10 operations
    values = claripy.BVS('values', 32 * 3)  # Assuming a maximum of 10 values

    state = shared.proj.factory.blank_state()
    # Allocate memory for the buffer and store the symbolic buffer in memory
    operations_buf_addr = state.solver.BVV(0x100000, 64)  # Example address to store the buffer
    state.memory.store(operations_buf_addr, operations)

    values_buf_addr = state.solver.BVV(0x100500, 64)  # Example address to store the buffer
    state.memory.store(values_buf_addr, values)

    shared.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(shared.proj.arch)

    # Create a call state for the function
    state = shared.proj.factory.call_state(run_heap_operations_addr, operations_buf_addr, values_buf_addr, count, cc=shared.mycc,
                                           prototype="void run_heap_operations(int *operations, int *values, int count);")

    # Add constraints to the symbolic variables if needed
    state.solver.add(count > 0)
    state.solver.add(count <= 3)  # Assuming a maximum of 10 operations

    # add constraint use chop to tell angr the charset
    for byte in operations.chop(32):
        state.add_constraints(byte >= 0)  # '\x20'
        state.add_constraints(byte <= 31339)  # '\x7e'

    for byte in values.chop(32):
        state.add_constraints(byte >= 0)  #
        state.add_constraints(byte <= 9)  #

    # 3 1 100 2 0 3 0
    #state.add_constraints(operations.chop(32)[0] == 1)
    state.add_constraints(operations.chop(32)[1] == 2)
    state.add_constraints(operations.chop(32)[2] == 3)

    state.add_constraints(values.chop(32)[0] == 8)
    state.add_constraints(values.chop(32)[1] == 0)
    state.add_constraints(values.chop(32)[2] == 0)

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    dispatcher = heap.HookDispatcher()
    heap_sanitizer = heap.HeapSanitizer(proj, dispatcher, shared)
    heap_sanitizer.install_hooks()

    state.inspect.b('call', when=angr.BP_BEFORE, action=angr_introspection.inspect_call)
    # state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    # state.inspect.b('address_concretization', when=angr.BP_AFTER, action=inspect_concretization)
    # state.inspect.b('mem_write', when=angr.BP_BEFORE, action=check_oob_write)

    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=heap_sanitizer.mem_write_hook)
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=heap_sanitizer.mem_read_hook)

    state.register_plugin("deep", state_plugin.SimStateDeepGlobals())
    state_plugin.SimStateDeepGlobals.register_default('deep')
    state.deep.memory_allocs = 0
    state.globals["allocations"]: Dict[int, int] = {}
    state.globals["freed_regions"]: List[Tuple[int, int]] = []


    proj.hook_symbol(0x1400014E0, libc.HookVPrintf())

    shared.state = state
    shared.simgr = proj.factory.simgr(state)
    shared.phase = 2

    logger.debug(shared.simgr.active[0].regs.rip)

    find_addresses = [should_have_crashed_addr]

    checks.check_find_addresses(find_addresses)

    #shared.simgr.use_technique(CFGFollower(cfg=shared.cfg, find=find_addresses))

    shared.simgr.explore(
        find=find_addresses,
        # avoid=[0x00000001400010E0],
        #step_func=check_for_vulns,
        cfg=shared.cfg
    )

    #shared.simgr.run()

    exploration_done([operations, values])


def main():
    shared.driver_path = sys.argv[1]

    try:
        shared.proj = angr.Project(shared.driver_path, auto_load_libs=False)
        logger.debug(f'analyze driver {shared.driver_path}')
    except:
        logger.error(f'cannot analyze {shared.driver_path}')
        sys.exit(-1)
    analyze(shared.proj)


if __name__ == "__main__":
    main()
