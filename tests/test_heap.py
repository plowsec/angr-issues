from typing import Dict, List, Tuple
from unittest.mock import patch

import angr
import logging
import claripy
from angr_analyze_function import exploration_done
from exploration_techniques.LeapFrogger import LeapFrogger

from helpers.log import logger
from helpers import shared, checks
from core import introspection, coverage
from targets.generic import libc
from sanitizers import heap

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("angr.exploration_techniques").setLevel(logging.DEBUG)
logging.getLogger("angr.storage").setLevel(logging.ERROR)
logging.getLogger("angr.engines").setLevel(logging.ERROR)
logging.getLogger("angr.misc").setLevel(logging.ERROR)
logging.getLogger("asyncio").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("claripy.backend").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("utils.graph").setLevel(logging.ERROR)
logging.getLogger("cle.backend").setLevel(logging.ERROR)
logging.getLogger("angr.misc").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins").setLevel(logging.ERROR)
logging.getLogger("angr.analyses.variable_recovery").setLevel(logging.ERROR)
logging.getLogger("angr.analyses.cfg").setLevel(logging.ERROR)
logging.getLogger("angr.analyses.complete_calling_conventions").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

import unittest


def log_and_pass(*args, **kwargs):
    str_args = " ".join([str(arg) for arg in args])

    logger.info(f"WARNING: {str_args}")
    return None


class TestHeap(unittest.TestCase):




    def setUp(self):

        shared.driver_path = "heap_bugs.exe"
        shared.proj = angr.Project(shared.driver_path, auto_load_libs=False)
        shared.cfg = shared.proj.analyses.CFGEmulated(fail_fast=True, normalize=True, keep_state=True)
        shared.proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True, cfg=shared.cfg)

        run_heap_operations_addr = 0x0000000140001200
        self.entry_point = run_heap_operations_addr
        count = claripy.BVS('count', 32)
        self.operations = claripy.BVS('operations', 32 * 3)  # Assuming a maximum of 10 operations
        operations = self.operations
        values = claripy.BVS('values', 32 * 3)  # Assuming a maximum of 10 values

        state = shared.proj.factory.blank_state()
        # Allocate memory for the buffer and store the symbolic buffer in memory
        operations_buf_addr = state.solver.BVV(0x100000, 64)  # Example address to store the buffer
        state.memory.store(operations_buf_addr, operations)

        values_buf_addr = state.solver.BVV(0x100500, 64)  # Example address to store the buffer
        state.memory.store(values_buf_addr, values)

        shared.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(shared.proj.arch)

        # Create a call state for the function
        self.state = shared.proj.factory.call_state(run_heap_operations_addr, operations_buf_addr, values_buf_addr,
                                                    count,
                                                    cc=shared.mycc,
                                                    prototype="void run_heap_operations(int *operations, int *values, int count);")
        state = self.state
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

        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

        dispatcher = heap.HookDispatcher()
        heap_sanitizer = heap.HeapSanitizer(shared.proj, dispatcher, shared)
        heap_sanitizer.install_hooks()

        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=heap_sanitizer.mem_write_hook)
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=heap_sanitizer.mem_read_hook)

        state.globals["allocations"]: Dict[int, int] = {}
        state.globals["freed_regions"]: List[Tuple[int, int]] = []
        state.globals["shadow_info"]: Dict[int, Tuple[int, int]] = {}

    @patch('helpers.log.logger.warning')
    def test_use_after_free(self, mock_warning, side_effect=log_and_pass):

        should_have_crashed_addr = 0x140001348
        potential_uaf_str_addr = 0x0000000140001144
        self.state.add_constraints(self.operations.chop(32)[0] == 31337)
        shared.proj.hook_symbol(0x0000000140001550, libc.HookVPrintf())  # printf

        shared.simgr = shared.proj.factory.simgr(self.state)
        find_addresses = [potential_uaf_str_addr, should_have_crashed_addr]
        checks.check_find_addresses(find_addresses)

        #shared.simgr.explore(
        shared.simgr.use_technique(LeapFrogger(bb_addresses=find_addresses))
        """
            find=find_addresses,
            num_find=len(find_addresses),
            # avoid=[0x00000001400010E0],
            #step_func=check_for_vulns,
            #cfg=shared.cfg
        )
        """

        shared.simgr.run(step_func=introspection.debug_step_func, n=1000)

        exploration_done()

        self.assertTrue(len(shared.simgr.found) > 0)
        mock_warning.assert_called_with(unittest.mock.ANY)  # Checks if warning was called with any argument

        introspection.pretty_print_callstack(shared.simgr.found[0], 20)
        called_with_substring = any('UaF at 0x140001166' in str(call_args) for call_args in mock_warning.call_args_list)
        self.assertTrue(called_with_substring, "Warning was not called with the expected substring")

    @patch('helpers.log.logger.warning', side_effect=log_and_pass)
    def test_double_free(self, mock_warning):

        should_have_crashed_addr = 0x140001348
        double_free_addr = 0x0000000140001176
        self.state.add_constraints(self.operations.chop(32)[0] == 31338)
        shared.proj.hook_symbol(0x0000000140001550, libc.HookVPrintf())

        shared.simgr = shared.proj.factory.simgr(self.state)

        # it is required to add an intermediate address for LeapFrogger to know how to continue and loop back to the free node
        find_addresses = [double_free_addr, 0x140001040, double_free_addr, should_have_crashed_addr]
        checks.check_find_addresses(find_addresses)

        shared.simgr.use_technique(LeapFrogger(bb_addresses=find_addresses))
        shared.simgr.run(step_func=introspection.debug_step_func, n=1000)

        exploration_done()

        self.assertTrue(len(shared.simgr.found) > 0)
        mock_warning.assert_called_with(unittest.mock.ANY)  # Checks if warning was called with any argument

        introspection.pretty_print_callstack(shared.simgr.found[0], 20)
        called_with_substring = any(
            '0x140100058] Double free detected' in str(call_args) for call_args in mock_warning.call_args_list)
        self.assertTrue(called_with_substring, "Warning was not called with the expected substring")
        for call_args in mock_warning.call_args_list:
            logger.info(call_args)


    @patch('helpers.log.logger.warning', side_effect=log_and_pass)
    def test_oob(self, mock_warning):

        should_have_crashed_addr = 0x140001348
        oob_addr = 0x14000112D
        self.state.add_constraints(self.operations.chop(32)[0] == 31339)
        shared.proj.hook_symbol(0x0000000140001550, libc.HookVPrintf())

        shared.simgr = shared.proj.factory.simgr(self.state)

        # it is required to add an intermediate address for LeapFrogger to know how to continue and loop back to the free node
        find_addresses = [oob_addr, should_have_crashed_addr]
        checks.check_find_addresses(find_addresses)
        #coverage.monitor_coverage(shared.proj, shared.cfg, self.entry_point, duration=60.0)
        monitor = coverage.CoverageMonitor(shared.proj, shared.cfg, self.entry_point, update_interval=3.0, coverage_dir="cov")
        monitor.start_monitoring()
        shared.simgr.use_technique(LeapFrogger(bb_addresses=find_addresses))
        shared.simgr.run(step_func=introspection.debug_step_func, n=1000)

        exploration_done()

        self.assertTrue(len(shared.simgr.found) > 0)
        mock_warning.assert_called_with(unittest.mock.ANY)  # Checks if warning was called with any argument

        introspection.pretty_print_callstack(shared.simgr.found[0], 20)
        called_with_substring = any(
            'OOB at' in str(call_args) for call_args in mock_warning.call_args_list)
        self.assertTrue(called_with_substring, "Warning was not called with the expected substring")
        for call_args in mock_warning.call_args_list:
            logger.info(call_args)

        monitor.stop_monitoring()
