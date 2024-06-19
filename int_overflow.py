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





def print_disassembly(state):
    try:
        block = state.project.factory.block(state.addr)
        disassembly = block.capstone

        for insn in disassembly.insns:
            logger.debug(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")

    except Exception as e:
        logger.debug(f"Error printing disassembly: {e}")


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




def resolve_operand_value(curr_state, statements, operand):
    if isinstance(operand, int):
        return resolve_tmp_value(curr_state, statements, operand, is_output=True)
    elif isinstance(operand, claripy.ast.bv.BV):
        return operand
    elif isinstance(operand, pyvex.expr.RdTmp):
        return resolve_tmp_value(curr_state, statements, operand.tmp)
    elif isinstance(operand, pyvex.expr.Const):
        return claripy.BVV(operand.con.value, operand.con.size)
    else:
        raise TypeError(f"Unsupported operand type: {type(operand)}")


def resolve_tmp_value(curr_state, statements, tmp, is_output=False):

    stmts = get_slice(statements, tmp)

    for stmt in stmts:
        logger.debug(f"stmt: {stmt.__str__()}")

    df = DataFlowAnalyzer(curr_state)
    tmp_values, tmp_taint, operand_map = df.process_irsb(stmts)
    return tmp_values[tmp]



def adjust_length(output_val, input_val):
    if output_val.length != input_val.length:
        logger.debug(f"Length mismatch: {output_val.length} != {input_val.length}")
        if output_val.length < input_val.length:
            input_val = claripy.Extract(output_val.length - 1, 0, input_val)
        else:
            input_val = claripy.ZeroExt(output_val.length - input_val.length, input_val)
    else:
        logger.debug(f"Good length: {output_val.length} == {input_val.length}")
    return input_val




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
                elif isinstance(stmt.data, pyvex.expr.RdTmp):
                    taint_set.add(stmt.data.tmp)
                else:
                    raise ValueError(f"Unhandled statement type: {type(stmt.data)}")

    return list(reversed(relevant_statements))


def check_tmp(state, stmt, output, input_val1, input_val2=None):
    tmps = state.scratch.temps

    if state.solver.satisfiable(
            extra_constraints=[tmps[output] < tmps[input_val1]]
    ):
        logger.debug("Overflow: %s" % pp_stmt(stmt, tmps, [input_val1, output]))
        return True

    if input_val2 is not None:
        if state.solver.satisfiable(
                extra_constraints=[tmps[output] < tmps[input_val2]]
        ):
            logger.debug("Overflow: %s" % pp_stmt(stmt, tmps, [input_val2, output]))
            return True

    return False


def all_temps_available(state, input_val1, input_val2, output):
    tmps = state.scratch.temps

    if len(tmps) < output or len(tmps) < input_val1 or len(tmps) < input_val2:
        return False
    if tmps[output] is None or tmps[input_val1] is None or tmps[input_val2] is None:
        return False

    return True


def check_overflow(curr_state, result, input1, input2, signed=False):
    state = curr_state.copy()
    solver = state.solver

    if signed:
        # Signed overflow detection
        sign_bit = result.size() - 1
        input1_sign = input1[sign_bit]
        input2_sign = input2[sign_bit]
        result_sign = result[sign_bit]

        # Overflow occurs if input1 and input2 have the same sign, but result has a different sign
        overflow_cond = claripy.And(input1_sign == input2_sign, input1_sign != result_sign)
    else:
        # Unsigned overflow detection
        overflow_cond = claripy.Or(result < input1, result < input2)

    solver.add(overflow_cond)
    if not solver.satisfiable():
        return False

    concrete_value1 = solver.eval(input1)
    concrete_value2 = solver.eval(input2)
    logger.warning(f"Concrete values that work are: {concrete_value1}, {concrete_value2}")


def check_symbolic_tmps(curr_state: angr.sim_state.SimState, statements, idx: int, stmt, output, input1, input2):
    print_disassembly(curr_state)

    output_val = resolve_operand_value(curr_state, statements, output)
    input1_val = resolve_operand_value(curr_state, statements, input1)
    input2_val = resolve_operand_value(curr_state, statements, input2)

    logger.debug(f"Constraints on output_val: {output_val}")
    if isinstance(output_val, claripy.ast.bv.BV) and isinstance(input1_val, claripy.ast.bv.BV) and isinstance(input2_val, claripy.ast.bv.BV):
        input1_val = adjust_length(output_val, input1_val)
        input2_val = adjust_length(output_val, input2_val)

        result = input1_val + input2_val
        is_signed = False
        logger.warning(f"Checking for overflow @ {hex(curr_state.addr)} ({output}, {input1}, {input2}: {input1_val} + {input2_val} = {result}")
        logger.debug(curr_state.solver.constraints)
        if check_overflow(curr_state, result, input1_val, input2_val, signed=is_signed):
            logger.warning("Possible overflow detected.")

        else:
            logger.warning("No values satisfy the condition.")
    else:
        logger.debug("Unsupported operand type")


def check_for_vulns(simgr, proj):
    if len(simgr.stashes["active"]) < 1:
        return False

    curr_state = simgr.stashes["active"][0]
    print_disassembly(curr_state)

    if curr_state.project.is_hooked(curr_state.addr):
        return False

    if curr_state.solver.symbolic(curr_state._ip):
        return True

    sym_obj = proj.loader.find_symbol(curr_state.addr, fuzzy=True)
    if sym_obj and sym_obj.name == "__libc_start_main.after_main":
        return True

    block = curr_state.block(curr_state.addr)
    logger.debug(f"Checking block at {hex(curr_state.addr)}")
    vex = block.vex
    cap = block.capstone

    rbp_off = curr_state.arch.registers["rbp"][0]
    rsp_off = curr_state.arch.registers["rsp"][0]


    for idx, stmt in enumerate(vex.statements):
        if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop):
            if not isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
                continue

            regs = get_regs(vex, idx)

            if rbp_off in regs or rsp_off in regs:
                continue

            mnemonic = cap.insns[get_capstone_from_vex(vex, idx)].mnemonic
            if (mnemonic.startswith("add") or mnemonic.startswith('inc')) and \
               (stmt.data.op.startswith("Iop_Add") or stmt.data.op.startswith("Iop_Shl")):
                logger.debug(f"Statement: {stmt}")
                logger.debug("Checking for overflow on t%d" % stmt.tmp)

                input1 = stmt.data.args[0]
                input2 = stmt.data.args[1]
                logger.debug(f"Inputs: {input1}, {input2}")
                check_symbolic_tmps(curr_state, vex.statements, idx, stmt, stmt.tmp, input1, input2)

            else:
                # TODO: mul and sub
                pass
