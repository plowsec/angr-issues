import angr
import claripy
import pyvex

from helpers.log import logger
from dataflow import DataFlowAnalyzer


def pp_stmt(stmt, temps, tmp_idxs):
    msg = str(stmt)
    for idx in tmp_idxs:
        msg = msg.replace("t%d" % idx, str(temps[idx]))
    return msg

def get_capstone_from_vex(vex, stmt_idx):
    """Given the index for a vex statement, return the corresponding capstone index."""
    slice = vex.statements[:stmt_idx]
    insns = 0
    for stmt in slice[::-1]:
        if isinstance(stmt, pyvex.stmt.IMark):
            insns += 1
    return insns - 1


def _taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given a non-OP IRExpr, add any tmps or regs to the provided sets.

    This is a helper for taint_irexpr and should not be called directly.
    """
    if not tainted_regs is None and isinstance(expr, pyvex.expr.Get):
        tainted_regs.append(expr.offset)
    elif isinstance(expr, pyvex.expr.RdTmp):
        tainted_tmps.add(expr.tmp)


def taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given an IRExpr, add any tmps or regs to the provided sets."""
    if isinstance(
            expr, (pyvex.expr.Qop, pyvex.expr.Triop, pyvex.expr.Binop, pyvex.expr.Unop)
    ):
        for arg in expr.args:
            _taint_irexpr(arg, tainted_tmps, tainted_regs)
    else:
        _taint_irexpr(expr, tainted_tmps, tainted_regs)


def get_regs(irsb, idx):
    """Returns all registers associated with the WrTmp statement at idx in irsb."""
    wrtmp = irsb.statements[idx]
    stmts = irsb.statements[
            : idx + 1
            ]  # all dependencies should come before WrTmp statement

    tainted_tmps = {wrtmp.tmp}
    tainted_regs = list()

    for stmt in stmts[::-1]:
        if isinstance(stmt, pyvex.stmt.Put) and isinstance(stmt.data, pyvex.expr.RdTmp):
            if stmt.data.tmp in tainted_tmps:
                tainted_regs.append(stmt.offset)
        elif isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
            taint_irexpr(stmt.data, tainted_tmps, tainted_regs)

    return set(tainted_regs)


def check_tmp(state, stmt, output, input_val):
    tmps = state.scratch.temps

    try:
        if state.solver.satisfiable(
                extra_constraints=[tmps[output] < tmps[input_val]]
        ):
            logger.debug("Overflow: %s" % pp_stmt(stmt, tmps, [input_val, output]))
            return True
    except claripy.errors.ClaripyOperationError:
        logger.warning("Claripy solver error while checking for overflow")


def all_temps_available(state, input_val, output):
    tmps = state.scratch.temps

    if len(tmps) < output or len(tmps) < input_val:
        return False
    if tmps[output] is None or tmps[input_val] is None:
        return False

    return True


def print_disassembly(state):
    block = state.project.factory.block(state.addr)
    disassembly = block.capstone

    for insn in disassembly.insns:
        logger.debug(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")


"""
0x140001080: mov dword ptr [rsp + 8], ecx
0x140001084: sub rsp, 0x38
0x140001088: mov eax, dword ptr [rsp + 0x40]
0x14000108c: add eax, 7 ; overflow here

0x14000108f: mov dword ptr [rsp + 0x20], eax
0x140001093: mov edx, dword ptr [rsp + 0x20]
0x140001097: lea rcx, [rip + 0x2262]
0x14000109e: call 0x1400012f0

manual proof:
        base_address = claripy.BVV(576460752303357848, 64)
        offset1 = claripy.BVV(0x38, 64)
        offset2 = claripy.BVV(0x40, 64)

        # Calculate the effective address
        effective_address = base_address - offset1 + offset2

        # Load the value from memory at the effective address
        value_in_memory = curr_state.memory.load(effective_address, size=4, endness=curr_state.arch.memory_endness)

        # Convert the loaded value to a 32-bit bit-vector
        value_in_memory_bv = claripy.BVS('value_in_memory_bv', 32)

        # Add a constraint to ensure value_in_memory_bv matches the loaded value
        curr_state.solver.add(value_in_memory_bv == value_in_memory)


        # Perform the addition
        const_to_add = claripy.BVV(0x00000007, 32)  # 32-bit constant
        result = value_in_memory_bv + const_to_add
"""


def check_symbolic_tmps(curr_state: angr.sim_state.SimState, statements, idx: int, stmt, output, input):
    print_disassembly(curr_state)

    temps = curr_state.scratch.temps

    if len(temps) < output or temps[output] is None:
        logger.debug(f"Symbolic output: {output}")
        # resolve the symbolic tmp
        stmts = get_slice(statements, output)
        print(stmts)
        df = DataFlowAnalyzer(curr_state)
        tmp_values, tmp_taint, operand_map = df.process_irsb(stmts)
        output_val = tmp_values[output]
    else:
        output_val = temps[output]

    if len(temps) < input or temps[input] is None:
        logger.debug(f"Symbolic input: {input}")
        # resolve the symbolic tmp1
        stmts = get_slice(statements, input)
        print(stmts)
        df = DataFlowAnalyzer(curr_state)
        tmp_values, tmp_taint, operand_map = df.process_irsb(stmts)
        input_val = tmp_values[input]
    else:
        input_val = temps[input]

    if isinstance(output_val, claripy.ast.bv.BV) and isinstance(input_val, claripy.ast.bv.BV):
        if output_val.length != input_val.length:
            logger.debug(f"Length mismatch: {output_val.length} != {input_val.length}")
            if output_val.length < input_val.length:
                input_val = claripy.Extract(output_val.length - 1, 0, input_val)
            else:
                logger.debug(f"Length mismatch: {output_val.length} != {input_val.length}")
        else:
            logger.debug(f"Good length: {output_val.length} == {input_val.length}")

        const_to_add_bv = claripy.BVV(stmt.data.args[1].con.value, 32)
        result = input_val + const_to_add_bv

        # Define the range constraints
        lower_bound = claripy.BVV(0, 32)
        upper_bound = const_to_add_bv

        # Create the condition for the range
        range_cond = claripy.And(result > lower_bound, result < upper_bound)
        #res = curr_state.solver.satisfiable(extra_constraints=[overflow_cond])
        # Add the range condition to the solver
        solver = curr_state.solver
        solver.add(range_cond)

        # Check if the range condition is satisfiable
        if res := solver.satisfiable():
            # Solve for a concrete value that satisfies the constraints
            concrete_value = solver.eval(input_val)
            print(f"A concrete value that works is: {concrete_value}")

        else:
            print("No value satisfies the condition.")
        logger.debug(f"Integer overflow: {res}")
    pass


def get_slice(statements, target_tmp):
    relevant_statements = []
    taint_set = set([target_tmp])

    for stmt in reversed(statements):
        if hasattr(stmt, 'data') and hasattr(stmt, 'tmp'):
            if stmt.tmp in taint_set:
                relevant_statements.append(stmt)
                if isinstance(stmt.data, pyvex.expr.Get):
                    taint_set.add(stmt.data.offset)
                elif isinstance(stmt.data, pyvex.expr.Binop):
                    for arg in stmt.data.args:
                        if isinstance(arg, pyvex.expr.RdTmp):
                            taint_set.add(arg.tmp)
                elif isinstance(stmt.data, pyvex.expr.Load):
                    if isinstance(stmt.data.addr, pyvex.expr.RdTmp):
                        taint_set.add(stmt.data.addr.tmp)
                elif isinstance(stmt.data, pyvex.expr.Unop):
                    if isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
                        taint_set.add(stmt.data.args[0].tmp)
                elif isinstance(stmt.data, pyvex.expr.Const):
                    pass  # Constants do not add new taints
                else:
                    raise ValueError(f"Unhandled statement type: {type(stmt.data)}")

    return list(reversed(relevant_statements))


def check_for_vulns(simgr, proj):
    if len(simgr.stashes["active"]) < 1:
        return False

    # get current and previous states
    curr_state = simgr.stashes["active"][0]

    if curr_state.solver.symbolic(curr_state._ip):
        # cannot handle states with symbolic program counters
        return True

    sym_obj = proj.loader.find_symbol(curr_state.addr, fuzzy=True)
    if not sym_obj is None and sym_obj.name == "__libc_start_main.after_main":
        return True

    # we can analyze, check basic block for blown (over or underflown) bitvectors
    block = curr_state.block(curr_state.addr)
    vex = block.vex
    cap = block.capstone

    rbp_off = curr_state.arch.registers["rbp"][0]
    rsp_off = curr_state.arch.registers["rsp"][0]

    blown_tmps = dict()  # tmps that are over or underflowed, value is a tag
    for idx, stmt in enumerate(vex.statements):
        if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(
                stmt.data, pyvex.expr.Binop
        ):
            # check if binop is arithmetic that can over/underflow and if so, detect any blown tmps
            if not isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
                continue  # not a tmp

            regs = get_regs(vex, idx)

            if rbp_off in regs or rsp_off in regs:
                continue  # rsp and rbp manipulations are always lifted into overflowing statements

            mnemonic = cap.insns[get_capstone_from_vex(vex, idx)].mnemonic
            if (mnemonic.startswith("add") or mnemonic.startswith('inc')) and (
                    stmt.data.op.startswith("Iop_Add") or stmt.data.op.startswith("Iop_Shl")
            ):
                logger.debug("Checking for overflow on t%d" % stmt.tmp)
                input = stmt.data.args[0].tmp
                output = stmt.tmp
                if all_temps_available(curr_state, input, output):
                    if check_tmp(
                            curr_state, stmt, output, input
                    ):
                        logger.debug("t%d is overflowed" % stmt.tmp)
                else:
                    check_symbolic_tmps(curr_state, vex.statements, idx, stmt, output, input)

            else:
                # TODO: mul and sub
                pass
