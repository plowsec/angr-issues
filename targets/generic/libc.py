import angr

from helpers.log import logger
from angr.procedures.stubs.format_parser import FormatParser

class HookVPrintf(FormatParser):
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

        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        # The format str is at index 0
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        stdout.write_data(out_str, out_str.size() // 8)
        return out_str.size() // 8