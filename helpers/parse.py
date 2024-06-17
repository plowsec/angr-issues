import re

from helpers.log import logger


# Function to parse a line from the trace
def parse_line(line):
    parts = line.split('|')
    if len(parts) == 2:
        regs, instr = parts
        instr = instr.strip()
        return regs.strip(), instr
    return None, None


# Function to extract register values
def extract_reg_value(regs, reg_name):
    match = re.search(rf'{reg_name}=(0x[0-9a-fA-F]+)', regs)
    if match:
        return int(match.group(1), 16)
    return None



# extract memory read/write information from Tenet trace
def extract_mem_info(regs):
    logger.debug(f"Extracting memory info from: {regs}"[:1024])

    # Define the patterns for "mw", "mr", and "mwr"
    mw_pattern = re.compile(r'mw=0x([0-9a-fA-F]+):([0-9a-fA-F]+)')
    mr_pattern = re.compile(r'mr=0x([0-9a-fA-F]+):([0-9a-fA-F]+)')
    mwr_pattern = re.compile(r'mwr=0x([0-9a-fA-F]+):([0-9a-fA-F]+)')

    # Initialize a list to store the results
    results = []

    # Find all occurrences of "mwr" and add them to the results as both "mw" and "mr"
    for match in mwr_pattern.findall(regs):
        address, value = match
        results.append(('mw', int(address, 16), int(value, 16)))
        results.append(('mr', int(address, 16), int(value, 16)))

    # Remove "mwr" from the line to avoid double counting
    regs = mwr_pattern.sub('', regs)

    # Find all occurrences of "mw" and add them to the results
    for match in mw_pattern.findall(regs):
        address, value = match
        results.append(('mw', int(address, 16), int(value, 16)))

    # Find all occurrences of "mr" and add them to the results
    for match in mr_pattern.findall(regs):
        address, value = match
        results.append(('mr', int(address, 16), int(value, 16)))

    if results:
        for result in results:
            logger.debug(f"Memory operation found: {result}")
    else:
        logger.debug("No memory operation found.")

    return results