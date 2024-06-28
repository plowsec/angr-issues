from typing import Dict, Optional

import angr
import pdbparse
import os
import re
from typing import Optional
from helpers.log import logger
from cppmangle import demangle, cdecl_sym

class SymbolManager:
    """
    A class to manage symbols for an angr project.

    This class handles loading symbols from PDB files, demangling names,
    and mapping addresses to symbols.
    """

    def __init__(self, proj: angr.Project):
        """
        Initialize the SymbolManager.

        Args:
            proj (angr.Project): The angr project to analyze.
        """
        self.proj: angr.Project = proj
        self.pdb: pdbparse.PDB = self.load_symbols()
        self.symbols: Dict[int, str] = self.load_global_symbols()
        self.text_section_offset: int = self.get_text_section_offset()

    def load_symbols(self) -> pdbparse.PDB:
        """
        Load symbols for the angr project from a PDB file.

        Returns:
            pdbparse.PDB: The parsed PDB file.

        Raises:
            FileNotFoundError: If the PDB file is not found.
        """
        binary_path: str = self.proj.filename
        pdb_path: str = os.path.splitext(binary_path)[0] + ".pdb"

        if not os.path.exists(pdb_path):
            raise FileNotFoundError(f"PDB file not found: {pdb_path}")

        return pdbparse.parse(pdb_path)

    def load_global_symbols(self) -> Dict[int, str]:
        """
        Load global symbols from the PDB.

        Returns:
            Dict[int, str]: A dictionary mapping offsets to symbol names.
        """
        globals_symbols = {}
        for stream in self.pdb.streams:
            if hasattr(stream, 'funcs'):
                for sym, sym_value in stream.funcs.items():
                    globals_symbols[sym_value.offset] = sym_value.name
                    logger.debug(f"Global symbol: {sym_value.name} at {hex(sym_value.offset)}")
        return globals_symbols

    def get_text_section_offset(self) -> int:
        """
        Get the offset of the .text section from the image base.

        Returns:
            int: The offset of the .text section, or 0 if not found.
        """
        main_object = self.proj.loader.main_object
        for section_name, section in main_object.sections_map.items():
            if section_name.startswith('.text'):
                return section.vaddr - main_object.mapped_base

        logger.warning("Could not find .text section. Using 0 as offset.")
        return 0

    @staticmethod
    def demangle_name(mangled_name: str) -> str:
        """
        Demangle a C++ function name and extract just the function name.

        Args:
            mangled_name (str): The mangled function name.

        Returns:
            str: The demangled function name without parameters or return type.
        """
        try:
            full_demangled: str = cdecl_sym(demangle(mangled_name))
            match: Optional[re.Match] = re.search(r'(?:.*::)?(\w+)\(', full_demangled)
            return match.group(1) if match else full_demangled
        except:
            return mangled_name

    def address_to_symbol(self, address: int) -> Optional[str]:
        """
        Convert an address to a symbol name.

        Args:
            address (int): The address to look up.

        Returns:
            Optional[str]: The symbol name if found, None otherwise.
        """
        rva: int = address - self.proj.loader.main_object.mapped_base

        symbol: Optional[str] = self.symbols.get(rva)
        if symbol:
            return symbol

        adjusted_rva: int = rva - self.text_section_offset
        symbol = self.symbols.get(adjusted_rva)
        if symbol:
            return symbol

        logger.warning(f"Symbol not found for address {hex(address)} (RVA: {hex(rva)}, Adjusted RVA: {hex(adjusted_rva)})")
        return None

    def update_kb_with_symbols(self):
        """
        Update the knowledge base with symbols.

        This method updates the names of functions in the angr knowledge base
        with demangled symbols from the PDB.
        """
        for func in self.proj.kb.functions.values():
            symbol = self.address_to_symbol(func.addr)
            if symbol:
                demangled = self.demangle_name(symbol)
                func.name = demangled
                logger.debug(f"Function {hex(func.addr)} updated with symbol: {func.name}")