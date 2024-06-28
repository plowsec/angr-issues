import os
import time
import threading
from typing import Dict, List, Tuple, Set, Any
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.animation import FuncAnimation
import angr
import logging

logger = logging.getLogger(__name__)

logging.getLogger("matplotlib").setLevel(logging.ERROR)


class CoverageMonitor:
    def __init__(self, proj: angr.Project, cfg: angr.analyses.CFGEmulated, entry_point: int,
                 update_interval: float = 5.0, coverage_dir: str = "cov"):
        """
        Initialize the CoverageMonitor.

        :param proj: The Angr project
        :param cfg: The Control Flow Graph
        :param entry_point: The entry point address
        :param update_interval: The interval between updates in seconds
        """
        self.proj: angr.Project = proj
        self.cfg: angr.analyses.CFGEmulated = cfg
        self.entry_point: int = entry_point
        self.update_interval: float = update_interval
        self.coverage_data: Dict[str, List[Tuple[float, int, float]]] = {}
        self.overall_coverage_data: List[Tuple[float, float]] = []
        self.start_time: float = time.time()
        self.stop_event: threading.Event = threading.Event()
        self.previous_coverage: Dict[str, Dict[str, int]] = {}
        self.previous_total_blocks: int = 0
        self.previous_functions: Set[str] = set()
        self.coverage_dir: str = coverage_dir

    def start_monitoring(self) -> None:
        """Start the coverage monitoring thread."""

        # clear the coverage directory
        for filename in os.listdir(self.coverage_dir):
            if filename.startswith("00"):
                os.remove(os.path.join(self.coverage_dir, filename))

        self.monitoring_thread = threading.Thread(target=self._monitor_coverage)
        self.monitoring_thread.start()

    def stop_monitoring(self) -> None:
        """Stop the coverage monitoring thread."""
        self.stop_event.set()
        self.monitoring_thread.join()

    def _monitor_coverage(self) -> None:
        """Monitor the coverage and update the data periodically."""
        while not self.stop_event.is_set():
            self._update_coverage()
            self.plot_coverage()
            time.sleep(self.update_interval)

    def _analyze_coverage(self) -> Tuple[float, Dict[str, Dict[str, int]]]:
        """
        Analyze the current coverage using Angr.

        :return: A tuple containing overall coverage percentage and function-wise coverage data
        """
        overall_coverage, function_coverage = analyze_coverage(self.proj, self.cfg, self.entry_point, "cov")

        # Convert the function_coverage to the format we need
        formatted_coverage: Dict[str, Dict[str, int]] = {}
        for func_addr, data in function_coverage.items():
            func_name = self.proj.kb.functions.get(func_addr).name
            formatted_coverage[func_name] = {
                "covered_blocks": data['covered_blocks'],
                "total_blocks": data['total_blocks']
            }

        return overall_coverage, formatted_coverage

    def _update_coverage(self) -> None:
        """Update the coverage data and log the results."""
        overall_coverage, function_coverage = self._analyze_coverage()
        elapsed_time = time.time() - self.start_time

        total_blocks = 0
        new_functions = set(function_coverage.keys()) - self.previous_functions

        logger.info(f"--- Coverage Update at {elapsed_time:.2f} seconds ---")

        for func_name, data in function_coverage.items():
            if func_name not in self.coverage_data:
                self.coverage_data[func_name] = []

            covered_blocks = data['covered_blocks']
            total_blocks += covered_blocks
            total_func_blocks = data['total_blocks']
            coverage_percentage = (covered_blocks / total_func_blocks) * 100 if total_func_blocks > 0 else 0

            self.coverage_data[func_name].append((elapsed_time, covered_blocks, coverage_percentage))

            # Calculate difference from previous update
            prev_covered = self.previous_coverage.get(func_name, {}).get('covered_blocks', 0)
            block_diff = covered_blocks - prev_covered

            if block_diff > 0 or func_name in new_functions:

                if covered_blocks == 0:
                    continue

                logger.info(f"Function: {func_name} - Covered blocks: {covered_blocks}/{total_func_blocks} "
                            f"({coverage_percentage:.2f}%) [+{block_diff} blocks]")

        # Log overall statistics
        new_total_blocks = total_blocks - self.previous_total_blocks
        logger.info(f"Overall coverage: {overall_coverage:.2f}% [+{new_total_blocks} blocks total]")
        if new_functions:
            logger.info(f"Newly discovered functions: {', '.join(new_functions)}")

        # Update overall coverage data
        self.overall_coverage_data.append((elapsed_time, overall_coverage))

        # Update previous state
        self.previous_coverage = function_coverage
        self.previous_total_blocks = total_blocks
        self.previous_functions = set(function_coverage.keys())

    def plot_coverage(self) -> None:
        """Plot the coverage evolution over time."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 12))

        # Plot overall coverage
        times, coverages = zip(*self.overall_coverage_data)
        ax1.plot(times, coverages, label='Overall Coverage', linewidth=2, color='black')
        ax1.set_xlabel('Time (seconds)')
        ax1.set_ylabel('Coverage (%)')
        ax1.set_title('Overall Coverage Evolution Over Time')
        ax1.legend()
        ax1.grid(True)

        # Plot function-wise coverage
        for func_name, data in self.coverage_data.items():
            times, _, coverages = zip(*data)
            ax2.plot(times, coverages, label=func_name)

        ax2.set_xlabel('Time (seconds)')
        ax2.set_ylabel('Coverage (%)')
        ax2.set_title('Function-wise Coverage Evolution Over Time')
        ax2.legend(loc='center left', bbox_to_anchor=(1, 0.5))
        ax2.grid(True)

        plt.tight_layout()
        plt.show()


def monitor_coverage(proj: angr.Project, cfg: angr.analyses.CFGEmulated, entry_point: int,
                     duration: float = 10.0, update_interval: int = 5) -> None:
    """
    Monitor the coverage evolution for a specified duration.

    :param proj: The Angr project
    :param cfg: The Control Flow Graph
    :param entry_point: The entry point address
    :param duration: The duration to monitor in seconds
    :param update_interval: The interval between updates in seconds
    """
    monitor = CoverageMonitor(proj, cfg, entry_point, update_interval=update_interval)
    monitor.start_monitoring()

    try:
        time.sleep(duration)
    finally:
        monitor.stop_monitoring()
        monitor.plot_coverage()


def get_reachable_info(cfg: angr.analyses.cfg.cfg_fast.CFGBase, entry_point: int) -> Tuple[
    Set[int], Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]]]:
    """
    Get reachable blocks and functions from the entry point in the CFG.

    Args:
        cfg: The control flow graph.
        entry_point: The entry point address.

    Returns:
        A tuple containing reachable blocks and reachable functions.
    """
    entry_node: angr.knowledge_plugins.cfg.cfg_node.CFGNode = cfg.get_any_node(entry_point)
    if not entry_node:
        raise ValueError(f"Entry point {hex(entry_point)} not found in CFG")

    reachable_nodes: Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = nx.descendants(cfg.graph, entry_node)
    reachable_nodes.add(entry_node)

    reachable_blocks: Set[int] = set(node.addr for node in reachable_nodes if node.block)

    reachable_functions: Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]] = {}
    for node in reachable_nodes:
        if node.function_address not in reachable_functions:
            reachable_functions[node.function_address] = set()
        reachable_functions[node.function_address].add(node)

    return reachable_blocks, reachable_functions


def read_coverage_files(coverage_dir: str) -> Set[int]:
    """
    Read coverage files and return a set of covered block addresses.

    Args:
        coverage_dir: The directory containing coverage files.

    Returns:
        A set of covered block addresses.
    """
    covered_blocks: Set[int] = set()
    for filename in os.listdir(coverage_dir):
        if filename.startswith("00"):
            with open(os.path.join(coverage_dir, filename), 'r') as f:
                covered_blocks.update(int(line.strip(), 16) for line in f if line.strip())
    return covered_blocks


def compare_coverage(proj: angr.Project, reachable_blocks: Set[int],
                     reachable_functions: Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]],
                     covered_blocks: Set[int]) -> Tuple[float, Dict[str, Dict[str, Any]]]:
    """
    Compare coverage between reachable blocks and covered blocks.

    Args:
        proj: The angr project.
        reachable_blocks: Set of reachable block addresses.
        reachable_functions: Dictionary of reachable functions and their nodes.
        covered_blocks: Set of covered block addresses.

    Returns:
        A tuple containing overall coverage and function coverage information.
    """
    total_reachable: int = len(reachable_blocks)
    total_covered: int = len(covered_blocks.intersection(reachable_blocks))
    overall_coverage: float = total_covered / total_reachable if total_reachable > 0 else 0

    function_coverage: Dict[str, Dict[str, Any]] = {}
    for func_addr, nodes in reachable_functions.items():
        func: angr.knowledge_plugins.functions.function.Function = proj.kb.functions.get(func_addr)
        if func:
            func_blocks: Set[int] = set(node.addr for node in nodes if node.block)
            covered_func_blocks: Set[int] = func_blocks.intersection(covered_blocks)
            coverage: float = len(covered_func_blocks) / len(func_blocks) if func_blocks else 0
            function_coverage[func.name] = {
                'address': func_addr,
                'total_blocks': len(func_blocks),
                'covered_blocks': len(covered_func_blocks),
                'coverage': coverage
            }

    return overall_coverage, function_coverage


def analyze_coverage(proj: angr.Project, cfg: angr.analyses.cfg.cfg_fast.CFGBase, entry_point: int,
                     coverage_dir: str, coverage_file: str = 'reachable_blocks.txt') -> Tuple[float, Dict[str, Dict[str, Any]]]:
    """
    Analyze coverage for the given project and CFG.

    Args:
        proj: The angr project.
        cfg: angr control flow graph.
        entry_point: The entry point address.
        coverage_dir: The directory containing coverage files.
        coverage_file: The coverage file to write to

    Returns:
        A tuple containing overall coverage and function coverage information.
    """
    reachable_blocks, reachable_functions = get_reachable_info(cfg, entry_point)
    covered_blocks = read_coverage_files(coverage_dir)
    overall_coverage, function_coverage = compare_coverage(proj, reachable_blocks, reachable_functions, covered_blocks)

    """
    logger.info(f"Total reachable blocks: {len(reachable_blocks)}")
    logger.info(f"Total covered blocks: {len(covered_blocks)}")
    logger.info(f"Overall coverage: {overall_coverage * 100:.2f}%")

    logger.info("\nFunction Coverage:")
    for func_name, data in function_coverage.items():
        logger.info(f"{func_name} (0x{data['address']:x}):")
        logger.info(f"  Total blocks: {data['total_blocks']}")
        logger.info(f"  Covered blocks: {data['covered_blocks']}")
        logger.info(f"  Coverage: {data['coverage'] * 100:.2f}%")
    """

    with open(coverage_file, 'w') as f:
        f.write("\n".join([hex(block) for block in reachable_blocks]))

    return overall_coverage, function_coverage