import archinfo
import pyvex

from helpers.log import logger

# Initialize the architecture
arch = archinfo.ArchAMD64()

def can_handle_instruction(instr, irsb):
    can_handle = not any(isinstance(stmt.data, pyvex.expr.CCall) for stmt in irsb.statements if hasattr(stmt, 'data'))
    can_handle = can_handle and not "gs:" in instr
    can_handle = can_handle and not "ret" in instr
    return can_handle


# Function to lift an instruction to VEX IR and analyze it
def analyze_instruction(instr_bytes, rip):
    logger.debug(f"Lifting instruction at RIP: {hex(rip)}")
    arch = archinfo.ArchAMD64()
    irsb = pyvex.lift(instr_bytes, rip, arch)
    return irsb


# Get the register name from the offset using archinfo
def get_register_name(offset):
    reg_name = arch.register_names.get(offset, None)
    if reg_name.startswith("ymm"):
        return reg_name.replace("ymm", "xmm")

    return reg_name