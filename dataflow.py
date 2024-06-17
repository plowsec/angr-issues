from typing import Dict, Any, Tuple

import angr
import networkx as nx
import pyvex

from helpers import lift
from helpers.log import logger
from helpers.operand import OperandKind, StackVariableOperand, RegisterOperand


class DataFlowAnalyzer:
    def __init__(self, state: angr.sim_state.SimState):

        self.stack_variables = {}
        self.digraph = nx.DiGraph()  # Initialize the directed graph
        self.timestamp = 0  # Initialize a timestamp or sequence number
        self.register_history = {}  # Dictionary to map register names to their history of nodes
        self.memory_history = {}  # Dictionary to map memory addresses to their history of nodes
        self.alias_history = {}  # Dictionary to map memory aliases to their history of nodes
        self.alias_to_mem = {}
        self.mem_to_alias = {}

        self.accessed_registers = set()  # Initialize a set to store the accessed registers
        self.statements = []  # List to store the statement nodes
        self.tmp_to_stmt = {}  # Map from temporary variables to statement nodes
        self.current_rip = 0  # Initialize the current instruction pointer
        self.current_instruction = ""  # Initialize the current instruction
        self.created_nodes = {}

        self.state: angr.sim_state.SimState = state


    # Function to get the value of a temporary variable
    @staticmethod
    def get_tmp_value(tmp, tmp_values):
        return tmp_values.get(tmp, None)


    # Function to perform intra-instruction taint analysis
    def handle_wr_tmp(self, stmt, tmp_values, tmp_taint, operand_map):

        """Handle WrTmp statements."""
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            self.handle_wr_tmp_rdtmp(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Unop):
            self.handle_wr_tmp_unop(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Load):
            self.handle_wr_tmp_load(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Get):
            self.handle_wr_tmp_get(stmt, tmp_values, tmp_taint, operand_map)
        elif isinstance(stmt.data, pyvex.expr.Const):
            self.handle_wr_tmp_const(stmt, tmp_values, tmp_taint)
        elif isinstance(stmt.data, pyvex.expr.Binop):
            self.handle_wr_tmp_binop(stmt, tmp_values, tmp_taint, operand_map)
        else:
            logger.error(f"WrTmp statement with data type {type(stmt.data)} not implemented")

    def handle_wr_tmp_rdtmp(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements with RdTmp data."""
        src_tmp = stmt.data.tmp
        tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
        logger.debug(
            f"RdTmp: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")

    def handle_wr_tmp_unop(self, stmt, tmp_values, tmp_taint, operand_map):

        """Handle WrTmp statements with Unop data."""
        if isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
            src_tmp = stmt.data.args[0].tmp
            if tmp_values.get(src_tmp) is None:
                logger.error(f"Unop: Source temp value is None, stmt={stmt}")
            tmp_values[stmt.tmp] = tmp_values.get(src_tmp)
            logger.debug(
                f"Unop: src_tmp={src_tmp}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
            if src_tmp in operand_map:
                operand_map[stmt.tmp] = operand_map[src_tmp]



    def handle_wr_tmp_load(self, stmt, tmp_values, tmp_taint, operand_map):

        """Handle WrTmp statements with Load data."""
        if isinstance(stmt.data.addr, pyvex.expr.Const):
            addr = stmt.data.addr.con.value
            tmp_values[stmt.tmp] = self.stack_variables.get(addr).value if addr in self.stack_variables else 0
            logger.debug(
                f"Load: addr={hex(addr)}, tmp_values[{stmt.tmp}]={hex(tmp_values[stmt.tmp])}")
            if addr in self.stack_variables:
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
            else:
                logger.debug(f"Creating stack variable for address: {hex(addr)}")
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, 0, "unknown")

                operand_map[stmt.tmp] = self.stack_variables.get(addr)



        else:

            logger.debug(f"Load: Address is not a constant, stmt={stmt}")

            addr_tmp = stmt.data.addr.tmp
            addr = tmp_values.get(addr_tmp)

            if addr is None:
                logger.error(f"Load: Address temp value is None, stmt={stmt}")
                raise ValueError(f"Load: Address temp value is None, stmt={stmt}")

            if addr in self.stack_variables:
                operand_map[stmt.tmp] = self.stack_variables.get(addr)
            else:
                logger.debug(f"Creating stack variable for address: {addr}")
                load_size = int(stmt.data.ty.split("_I")[1])
                value = self.state.memory.load(addr, load_size // 8, endness="Iend_LE")
                if value is None:
                    logger.warning(f"Memory value at address {addr} is None")
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, value, "unknown")
                operand_map[stmt.tmp] = self.stack_variables.get(addr)


            new_tmp_value = self.stack_variables.get(addr).value if addr in self.stack_variables else None

            if new_tmp_value is None:
                logger.error(f"Load: New temp value is None, stmt={stmt}")
                dbg_addr_in_stack = addr in self.stack_variables
                dbg_stack_variables = self.stack_variables.get(addr)
                dbg_stack_var_value = self.stack_variables.get(addr).value
                raise ValueError(f"Load: New temp value is None, stmt={stmt}")

            tmp_values[stmt.tmp] = new_tmp_value
            logger.debug(
                f"Load: addr_tmp={addr_tmp}, addr={addr}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")


    def handle_wr_tmp_get(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle WrTmp statements with Get data."""
        reg_name = lift.get_register_name(stmt.data.offset)
        load_size = int(stmt.data.ty.split("_I")[1])
        new_tmp_value = self.state.registers.load(stmt.data.offset, load_size // 8)

        if new_tmp_value is None:
            logger.error(f"Get: New temp value is None, stmt={stmt}")
            raise ValueError(f"Get: New temp value is None, stmt={stmt}")

        tmp_values[stmt.tmp] = new_tmp_value


        logger.debug(
            f"Get: reg_name={reg_name}, tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")


    def handle_wr_tmp_const(self, stmt, tmp_values, tmp_taint):
        """Handle WrTmp statements with Const data."""
        tmp_values[stmt.tmp] = stmt.data.con.value
        tmp_taint[stmt.tmp] = None
        logger.debug(
            f"Const: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")

    def handle_wr_tmp_binop(self, stmt, tmp_values, tmp_taint, operand_map):


        """Handle WrTmp statements with Binop data."""
        arg0 = self.get_tmp_value(stmt.data.args[0].tmp, tmp_values) if isinstance(stmt.data.args[0],
                                                                                   pyvex.expr.RdTmp) else \
            stmt.data.args[0].con.value if isinstance(stmt.data.args[0], pyvex.expr.Const) else None
        arg1 = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else self.get_tmp_value(
            stmt.data.args[1].tmp, tmp_values)
        if isinstance(stmt.data.args[0], pyvex.expr.RdTmp) and isinstance(stmt.data.args[1], pyvex.expr.RdTmp):
            self.handle_binop_both_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        elif isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
            self.handle_binop_first_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        elif isinstance(stmt.data.args[1], pyvex.expr.RdTmp):
            self.handle_binop_second_rdtmp(stmt, tmp_values, operand_map, arg0, arg1)
        self.handle_binop_operations(stmt, tmp_values, arg0, arg1)

    def handle_binop_both_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with both RdTmp arguments."""
        operand1 = operand_map.get(stmt.data.args[0].tmp)
        operand2 = operand_map.get(stmt.data.args[1].tmp)
        rd_tmp1 = stmt.data.args[0].tmp
        rd_tmp2 = stmt.data.args[1].tmp
        if rd_tmp1 in tmp_values and rd_tmp2 in tmp_values:
            if stmt.data.op.startswith('Iop_Add'):
                tmp_values[stmt.tmp] = tmp_values[rd_tmp1] + tmp_values[rd_tmp2]
                operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, tmp_values[stmt.tmp],
                                                        tmp_values[rd_tmp1] + tmp_values[rd_tmp2], "unknown")
            else:
                logger.error(f"Binop with both RdTmp: Not handled, stmt={stmt}")
        else:
            logger.error(f"Binop: One of the arguments is None, arg0={arg0}, arg1={arg1}")

    def handle_binop_first_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with the first argument as RdTmp."""
        operand = operand_map.get(stmt.data.args[0].tmp)
        if operand is None:
            logger.warning(f"Binop: Operand is None, stmt={stmt}")
            return
        if isinstance(operand, StackVariableOperand):
            offset = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else None
            if offset is not None:
                name = f"rsp+{hex(offset)}"
                address = operand.address + offset
                operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, address, operand.value, name)
                logger.debug(f"Stack variable offset: {name}, address={address}, pyvex_name={stmt.tmp}")

            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")
        else:
            offset = stmt.data.args[1].con.value if isinstance(stmt.data.args[1], pyvex.expr.Const) else None
            if offset is not None:
                name = f"{operand.name}+{hex(offset)}"
                tmp_val = tmp_values.get(stmt.data.args[0].tmp)
                if isinstance(tmp_val, int):  # TODO: get rid of those tuples
                    address = tmp_val + offset
                else:
                    address = tmp_val[0] + offset
                operand_map[stmt.tmp] = RegisterOperand(OperandKind.SOURCE, address,
                                                        tmp_values.get(stmt.data.args[0].tmp),
                                                        name)
                logger.debug(f"Register + offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")

    def handle_binop_second_rdtmp(self, stmt, tmp_values, operand_map, arg0, arg1):
        """Handle Binop with the second argument as RdTmp."""
        operand = operand_map.get(stmt.data.args[1].tmp)
        if isinstance(operand, StackVariableOperand):
            offset = stmt.data.args[0].con.value if isinstance(stmt.data.args[0], pyvex.expr.Const) else None
            if offset is not None:
                name = f"rsp+0x{hex(offset)}"
                address = operand.address + offset
                operand_map[stmt.tmp] = StackVariableOperand(OperandKind.SOURCE, address, operand.value, name)
                logger.debug(f"Stack variable offset: {name}, address={hex(address)}, pyvex_name={stmt.tmp}")

            else:
                logger.error(f"Binop: Stack variable offset is None, stmt={stmt}")

    def handle_binop_operations(self, stmt, tmp_values, arg0, arg1):
        """Handle Binop operations."""
        if stmt.data.op.startswith('Iop_Add') or stmt.data.op.startswith('Iop_And') or stmt.data.op.startswith(
                'Iop_Sub') or stmt.data.op.startswith('Iop_Xor') or stmt.data.op.startswith(
            'Iop_Shl') or stmt.data.op.startswith('Iop_Or') or stmt.data.op.startswith('Iop_Mul') or stmt.data.op.startswith('Iop_Shr'):
            if arg0 is not None and arg1 is not None:
                size_in_bits = stmt.data.tag_int * 8
                mask = (1 << size_in_bits) - 1
                if stmt.data.op.startswith('Iop_Add'):
                    result = (arg0 + arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(
                        f"Binop Add: tmp_values[{stmt.tmp}]={arg0}+{arg1} = {tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_And'):
                    result = (arg0 & arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop And: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Sub'):
                    result = (arg0 - arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Sub: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Xor'):
                    result = (arg0 ^ arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Xor: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Shl'):
                    result = (arg0 << arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Shl: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Or'):
                    result = (arg0 | arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Or: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Mul'):
                    result = (arg0 * arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Mul: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
                elif stmt.data.op.startswith('Iop_Shr'):
                    result = (arg0 >> arg1) & mask
                    tmp_values[stmt.tmp] = result
                    logger.debug(f"Binop Shr: tmp_values[{stmt.tmp}]={tmp_values[stmt.tmp]}")
            else:
                logger.error(
                    f"Binop {stmt.data.op.split('_')[1]}: One of the arguments is None, arg0={arg0}, arg1={arg1}")
        else:
            logger.error(f"Binop: Operation not handled, stmt={stmt}")

    def handle_put(self, stmt, tmp_values, tmp_taint):
        """Handle Put statements.
^        """
        reg_name = lift.get_register_name(stmt.offset)
        if reg_name.startswith("cc"):
            logger.debug(f"Skipping condition code register: {reg_name}")
            return
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp

            logger.debug(
                f"RdTmp: reg_name={reg_name}, src_tmp={src_tmp}")

        elif isinstance(stmt.data, pyvex.expr.Const):
            logger.debug(
                f"Const: reg_name={reg_name}")

    def handle_store(self, stmt, tmp_values, tmp_taint, operand_map):
        """Handle Store statements.
        """
        if isinstance(stmt.data, pyvex.expr.RdTmp):
            src_tmp = stmt.data.tmp
            operand_map[src_tmp].kind = OperandKind.SOURCE
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.addr.tmp
                addr = tmp_values.get(addr_tmp)
                operand_map[stmt.addr.tmp].kind = OperandKind.DESTINATION
                logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={hex(addr)}")

                if addr is not None:
                    self.stack_variables[addr] = operand_map[stmt.addr.tmp]
                    if isinstance(self.stack_variables[addr].value, tuple):
                        self.stack_variables[addr].value = self.stack_variables[addr].value[0]


                    logger.debug(
                        f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}")
            else:
                addr = stmt.addr.con.value
                logger.debug(f"Const addr: addr={addr}")
                if addr is not None:

                    self.stack_variables[addr] = operand_map[stmt.data.tmp]
                    if isinstance(self.stack_variables[addr].value, tuple):
                        self.stack_variables[addr].value = self.stack_variables[addr].value[0]
                    logger.debug(
                        f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}")
        elif isinstance(stmt.data, pyvex.expr.Const):
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                addr_tmp = stmt.addr.tmp
                addr = tmp_values.get(addr_tmp)
                logger.debug(f"RdTmp addr: addr_tmp={addr_tmp}, addr={hex(addr)}")
            else:
                addr = stmt.addr.con.value
                logger.debug(f"Const addr: addr={addr}")
            if addr is not None:
                self.stack_variables[addr] = StackVariableOperand(OperandKind.SOURCE, addr, stmt.data.con.value,
                                                                  "unknown")
                logger.debug(
                    f"Store: addr={addr}, stack_variables[{addr}]={self.stack_variables[addr].value}")
        else:
            logger.error(f"Store statement with data type {type(stmt.data)} not implemented")

    def intra_instruction_taint_analysis(self, stmts) -> Tuple[Dict[int, Any], Dict[int, Any], Dict[int, Any]]:
        """Perform intra-instruction taint analysis on the given IRSB."""
        tmp_values = {}
        tmp_taint = {}
        operand_map = {}
        logger.debug("Starting intra-instruction taint analysis")
        index = 0
        for stmt in stmts:
            logger.debug(f"Processing statement: {stmt}")
            if isinstance(stmt, pyvex.stmt.WrTmp):
                logger.debug(f"Handling WrTmp statement: {stmt}")
                self.handle_wr_tmp(stmt, tmp_values, tmp_taint, operand_map)
            elif isinstance(stmt, pyvex.stmt.Put):
                logger.debug(f"Handling Put statement: {stmt}")
                self.handle_put(stmt, tmp_values, tmp_taint)
            elif isinstance(stmt, pyvex.stmt.Store):
                logger.debug(f"Handling Store statement: {stmt}")
                self.handle_store(stmt, tmp_values, tmp_taint, operand_map)
            elif isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint) or isinstance(stmt,
                                                                                                          pyvex.stmt.Exit):
                pass
            else:
                raise NotImplementedError(f"Statement {type(stmt)} not implemented")

            index += 1

        logger.debug("Completed intra-instruction taint analysis")
        return tmp_values, tmp_taint, operand_map

    # Function to process IRSB and track taint flows
    def process_irsb(self, stmts):
        tmp_values, tmp_taint, operand_map = self.intra_instruction_taint_analysis(stmts)
        logger.debug(f"tmp_values: {tmp_values}")
        logger.debug(f"tmp_taint: {tmp_taint}")
        logger.debug(f"operand_map: {operand_map}")

        return tmp_values, tmp_taint, operand_map

