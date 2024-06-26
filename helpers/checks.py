from helpers.log import logger
from helpers import shared


def check_find_addresses(find_addresses):
    for f in find_addresses:
        nodes = shared.cfg.model.get_all_nodes(f)
        if len(nodes) == 0:
            logger.critical(f"Node not found for address {hex(f)}. Specify the start of a basic block.")
            func = shared.proj.kb.functions.floor_func(f)

            if func is None:
                logger.critical(f"This address is not even within a function.")
                return False

            # enumerate all basic blocks and check if the address is within the range of any block
            for block in func.blocks:
                if block.addr <= f < block.addr + block.size:
                    logger.debug(f"Try this one? {block}. Your address is in it.")
                    break

            return False

    return True