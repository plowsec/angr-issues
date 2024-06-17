
from enum import Enum
from helpers.log import logger

class OperandKind(Enum):
    SOURCE = "source"
    DESTINATION = "destination"

class NodeKind(Enum):
    REGISTER = 1
    STACK = 2
    MEMORY = 3
    CONST = 4

class Operand:
    def __init__(self, kind, value, location_kind):
        self.kind = kind
        self.value = value
        self.location_kind = location_kind


class StackVariableOperand(Operand):
    def __init__(self, kind, address, value, name):
        super().__init__(kind, value, NodeKind.STACK)
        self.address = address
        self.name = name

        if isinstance(value, tuple):
            raise ValueError(f"Stack variable value is a tuple, address={hex(address)}, name={name}")

        if value is None:
            logger.error(f"Stack variable value is None, address={hex(address)}, name={name}")
            # raise ValueError(f"Stack variable value is None, address={hex(address)}, name={name}")


class RegisterOperand(Operand):
    def __init__(self, kind, address, value, name):
        super().__init__(kind, value, NodeKind.REGISTER)
        self.address = address
        self.name = name