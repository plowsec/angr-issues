import angr

from helpers.log import logger

class HookVPrintf(angr.SimProcedure):
    def run(self, fmt, arg):
        # Resolve the format string
        if self.state.solver.symbolic(fmt):
            fmt_str = self.state.solver.eval(fmt)
        else:
            fmt_str = self.state.mem[fmt].string.concrete

        # Read the argument (assuming it's a string pointer)
        if self.state.solver.symbolic(arg):
            arg_str = self.state.solver.eval(arg)
        else:
            arg_str = self.state.mem[arg].string
            try:
                arg_str = arg_str.concrete.decode('utf-8')
            except:
                arg_str = ""

        # check if arg_str can be an int:
        try:
            arg_str = hex(int(arg_str))
        except:
            pass

        # Print the resolved strings
        logger.debug(f"Format: {fmt_str}")
        logger.debug(f"Argument: {arg_str}")