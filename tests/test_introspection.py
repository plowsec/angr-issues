import unittest
import angr
from core import introspection
import logging
import claripy
from angr_analyze_function import exploration_done
from exploration_techniques.LeapFrogger import LeapFrogger

from helpers.log import logger
from helpers import shared, checks
from core import introspection, coverage
from targets.generic import libc
from sanitizers import heap
from targets.windows import symbols

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


class TestIntrospection(unittest.TestCase):

    def setUp(self):
        shared.driver_path = "heap_bugs.exe"
        shared.proj = angr.Project(shared.driver_path, auto_load_libs=False)
        shared.cfg = shared.proj.analyses.CFGEmulated(fail_fast=True, normalize=True, keep_state=True)
        self.entry_point = 0x0000000140001200  # run_heap_operations_addr

    def test_reachability(self):

        reachable_blocks, reachable_functions = coverage.get_reachable_info(shared.cfg, self.entry_point)
        with open('reachable_blocks.txt', 'w') as f:
            f.write("\n".join([hex(block) for block in reachable_blocks]))

        for func in reachable_functions.keys():
            logger.info(f"Function: {shared.proj.kb.functions.get(func).name} ({len(reachable_functions[func])} nodes)")

        overall_coverage, function_coverage = coverage.analyze_coverage(shared.proj, shared.cfg, self.entry_point, "cov")

        self.assertGreater(overall_coverage, 0)
        self.assertGreater(len(function_coverage), 0)

        for func_name, data in sorted(function_coverage.items(), key=lambda x: x[1]['covered_blocks'], reverse=True):
            logger.info(f"Function: {func_name} ({data['covered_blocks']}/{data['total_blocks']} blocks covered)")


        #coverage.monitor_coverage(shared.proj, shared.cfg, self.entry_point, duration=60.0)
        monitor = coverage.CoverageMonitor(shared.proj, shared.cfg, self.entry_point, update_interval=3.0)
        monitor.start_monitoring()

    def test_symbols(self):

        symbol_manager = symbols.SymbolManager(shared.proj)
        symbol_manager.update_kb_with_symbols()
        pass
