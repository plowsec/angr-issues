import pickle

import angr
import sys
import IPython
import logging
import uuid

import claripy
import pyvex

from helpers.log import logger
import int_overflow
import globals
import hooks
import opcodes
import utils

import angr.calling_conventions
import angr.sim_type
from angr.state_plugins.plugin import SimStatePlugin
from copy import deepcopy


logging.basicConfig(level=logging.DEBUG)

class SimStateDeepGlobals(SimStatePlugin):
    """Based on angr's original globals state plugin, only difference is this one deep copies"""

    def __init__(self, backer=None):
        super(SimStateDeepGlobals, self).__init__()
        try:
            self._backer = deepcopy(backer) if backer is not None else {}
        except RecursionError:
            logger.warning("Failed to deep copy, using shallow instead")
            self._backer = backer if backer is not None else {}

    def set_state(self, state):
        pass

    def merge(
            self, others, merge_conditions, common_ancestor=None
    ):  # pylint: disable=unused-argument
        for other in others:
            for k in other.keys():
                if k not in self:
                    self[k] = other[k]

        return True

    def widen(self, others):  # pylint: disable=unused-argument
        logger.warning("Widening is unimplemented for globals")
        return False

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt=None):
        return self._backer.get(k, alt)

    def pop(self, k, alt=None):
        return self._backer.pop(k, alt)

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateDeepGlobals(dict(self._backer))


def __print_history(state):
    summary = False
    if len(list(state.history.parents)) > 10:
        summary = True
    history = list(state.history.parents)
    history_length = len(history)
    print("\t\thistory [%s]:" % (history_length))
    for index, state in enumerate(history):
        if (index < 3 and summary):
            print("\t\t\t%s" % (state))
        if (index == history_length - 5):
            print("\t\t\t...")
        if (index > history_length - 5):
            print("\t\t\t%s" % (state))


def save_analysis_state(project, simgr, filename_prefix="angr_analysis"):
    with open(f"{filename_prefix}_project.pkl", "wb") as project_file:
        pickle.dump(project, project_file, protocol=-1)

    with open(f"{filename_prefix}_simgr.pkl", "wb") as simgr_file:
        pickle.dump(simgr, simgr_file, protocol=-1)

    with open(f"{filename_prefix}_globals.pkl", "wb") as globals_file:
        pickle.dump({
            'FIRST_ADDR': globals.FIRST_ADDR,
            'DO_NOTHING': globals.DO_NOTHING,
            'mycc': globals.mycc,
            'cfg': globals.cfg,
            'driver_path': globals.driver_path,
            'phase': globals.phase
        }, globals_file, protocol=-1)

    with open(f"{filename_prefix}_state.pkl", "wb") as state_file:
        pickle.dump(state, state_file, protocol=-1)


def restore_analysis_state(filename_prefix="angr_analysis"):
    with open(f"{filename_prefix}_project.pkl", "rb") as project_file:
        globals.proj = pickle.load(project_file)

    with open(f"{filename_prefix}_simgr.pkl", "rb") as simgr_file:
        globals.simgr = pickle.load(simgr_file)

    with open(f"{filename_prefix}_globals.pkl", "rb") as globals_file:
        globals_data = pickle.load(globals_file)
        globals.FIRST_ADDR = globals_data['FIRST_ADDR']
        globals.DO_NOTHING = globals_data['DO_NOTHING']
        globals.mycc = globals_data['mycc']
        globals.cfg = globals_data['cfg']
        globals.driver_path = globals_data['driver_path']
        globals.phase = globals_data['phase']

    with open(f"{filename_prefix}_state.pkl", "rb") as state_file:
        globals.state = pickle.load(state_file)


def get_small_coverage(*args, **kwargs):
    """

    if not globals.proj.is_hooked(state.addr):
        block = globals.proj.factory.block(state.addr)

        if len(block.capstone.insns) == 1 and (
                block.capstone.insns[0].mnemonic.startswith("rep m")
                or block.capstone.insns[0].mnemonic.startswith("rep s")
        ):
            logger.debug(f"Hooking instruction {block.capstone.insns[0].mnemonic} @ {hex(state.addr)}")
            insn = block.capstone.insns[0]
            globals.proj.hook(state.addr, hooks.RepHook(insn.mnemonic.split(" ")[1]).run, length=insn.size)
    """
    sm = args[0]
    stashes = sm.stashes
    i = 0
    for simstate in stashes["active"]:
        state_history = ""

        for addr in simstate.history.bbl_addrs.hardcopy:
            write_address = hex(addr)
            state_history += "{0}\n".format(write_address)

        ip = hex(state.solver.eval(simstate.ip))
        uid = str(uuid.uuid4())
        sid = str(i).zfill(5)
        filename = "{0}_active_{1}_{2}".format(sid, ip, uid)

        with open(filename, "w") as f:
            f.write(state_history)
        i += 1


def inspect_call(state):
    human_str = state.project.loader.describe_addr(state.addr)
    logger.debug(
        f'call {hex(state.addr)} ({human_str}) from {hex(state.history.addr)} ({state.project.loader.describe_addr(state.addr)})')
    if "extern-address" in human_str:
        logger.warning(f"Implement hook for {hex(state.addr)} ({human_str})")
        pass


def next_base_addr(size=0x10000):
    v = globals.FIRST_ADDR
    globals.FIRST_ADDR += size
    return v


def init_analysis(angr_proj):
    logger.debug('init analysis')
    globals.DO_NOTHING = next_base_addr()
    globals.proj.hook(globals.DO_NOTHING, hooks.HookDoNothing(cc=globals.mycc))

    # Hook target kernel APIs.
    hooks.find_hook_func()
    globals.DO_NOTHING = utils.next_base_addr()
    globals.proj.hook(globals.DO_NOTHING, hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('memmove', hooks.HookMemcpy(cc=globals.mycc))
    globals.proj.hook_symbol('memcpy', hooks.HookMemcpy(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenSection', hooks.HookZwOpenSection(cc=globals.mycc))
    globals.proj.hook_symbol('RtlInitUnicodeString', hooks.HookRtlInitUnicodeString(cc=globals.mycc))
    globals.proj.hook_symbol('RtlCopyUnicodeString', hooks.HookRtlCopyUnicodeString(cc=globals.mycc))
    """    globals.proj.hook_symbol('IoStartPacket', hooks.HookIoStartPacket(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateDevice', hooks.HookIoCreateDevice(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateSymbolicLink', hooks.HookIoCreateSymbolicLink(cc=globals.mycc))"""
    globals.proj.hook_symbol('IoIs32bitProcess', hooks.HookIoIs32bitProcess(cc=globals.mycc))
    globals.proj.hook_symbol('RtlGetVersion', hooks.HookRtlGetVersion(cc=globals.mycc))
    globals.proj.hook_symbol('ExGetPreviousMode', hooks.HookExGetPreviousMode(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveGroupCount', hooks.HookKeQueryActiveGroupCount(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveProcessors', hooks.HookKeQueryActiveProcessors(cc=globals.mycc))
    globals.proj.hook_symbol('KeQueryActiveProcessorCountEx', hooks.HookKeQueryActiveProcessorCountEx(cc=globals.mycc))
    globals.proj.hook_symbol('ExInterlockedPopEntrySList', hooks.HookExInterlockedPopEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('ExQueryDepthSList', hooks.HookExQueryDepthSList(cc=globals.mycc))
    globals.proj.hook_symbol('ExpInterlockedPushEntrySList', hooks.HookExpInterlockedPushEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('ExpInterlockedPopEntrySList', hooks.HookExpInterlockedPopEntrySList(cc=globals.mycc))
    globals.proj.hook_symbol('PsGetVersion', hooks.HookPsGetVersion(cc=globals.mycc))
    globals.proj.hook_symbol('ExInitializeResourceLite', hooks.HookExInitializeResourceLite(cc=globals.mycc))
    globals.proj.hook_symbol('KeWaitForSingleObject', hooks.HookKeWaitForSingleObject(cc=globals.mycc))
    globals.proj.hook_symbol('RtlWriteRegistryValue', hooks.HookRtlWriteRegistryValue(cc=globals.mycc))
    globals.proj.hook_symbol('IoGetDeviceProperty', hooks.HookIoGetDeviceProperty(cc=globals.mycc))
    globals.proj.hook_symbol('KeReleaseMutex', hooks.HookKeReleaseMutex(cc=globals.mycc))
    globals.proj.hook_symbol('MmGetSystemRoutineAddress', hooks.HookMmGetSystemRoutineAddress(cc=globals.mycc))
    globals.proj.hook_symbol('FltGetRoutineAddress', hooks.HookFltGetRoutineAddress(cc=globals.mycc))
    globals.proj.hook_symbol('RtlGetElementGenericTable', hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('ExAcquireResourceExclusiveLite', hooks.HookDoNothing(cc=globals.mycc))
    globals.proj.hook_symbol('ProbeForRead', hooks.HookProbeForRead(cc=globals.mycc))
    globals.proj.hook_symbol('ProbeForWrite', hooks.HookProbeForWrite(cc=globals.mycc))
    globals.proj.hook_symbol('MmIsAddressValid', hooks.HookMmIsAddressValid(cc=globals.mycc))
    globals.proj.hook_symbol('ZwQueryInformationFile', hooks.HookZwQueryInformationFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwQueryInformationProcess', hooks.HookZwQueryInformationProcess(cc=globals.mycc))
    globals.proj.hook_symbol("ObReferenceObjectByHandle", hooks.HookObReferenceObjectByHandle(cc=globals.mycc))
    globals.proj.hook_symbol("ZwWriteFile", hooks.HookZwWriteFile(cc=globals.mycc))
    globals.proj.hook_symbol("ZwCreateKey", hooks.HookZwCreateKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwOpenKey", hooks.HookZwOpenKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwDeleteValueKey", hooks.HookZwDeleteValueKey(cc=globals.mycc))
    globals.proj.hook_symbol("ZwQueryValueKey", hooks.HookZwQueryValueKey(cc=globals.mycc))
    globals.proj.hook_symbol("NdisRegisterProtocolDriver", hooks.HookNdisRegisterProtocolDriver(cc=globals.mycc))

    # Only hook for phase 2 to hunt vulnerabilities.
    globals.proj.hook_symbol("ExAllocatePool", hooks.HookExAllocatePool(cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePool2", angr.procedures.SIM_PROCEDURES['libc']['malloc'](cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePool3", hooks.HookExAllocatePool3(cc=globals.mycc))
    globals.proj.hook_symbol("MmAllocateNonCachedMemory", hooks.HookMmAllocateNonCachedMemory(cc=globals.mycc))
    globals.proj.hook_symbol("ExAllocatePoolWithTag", hooks.HookExAllocatePoolWithTag(cc=globals.mycc))
    globals.proj.hook_symbol("MmAllocateContiguousMemorySpecifyCache",
                             hooks.HookMmAllocateContiguousMemorySpecifyCache(cc=globals.mycc))
    globals.proj.hook_symbol('MmMapIoSpace', hooks.HookMmMapIoSpace(cc=globals.mycc))
    globals.proj.hook_symbol('MmMapIoSpaceEx', hooks.HookMmMapIoSpaceEx(cc=globals.mycc))
    globals.proj.hook_symbol('HalTranslateBusAddress', hooks.HookHalTranslateBusAddress(cc=globals.mycc))
    globals.proj.hook_symbol('ZwMapViewOfSection', hooks.HookZwMapViewOfSection(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenProcess', hooks.HookZwOpenProcess(cc=globals.mycc))
    globals.proj.hook_symbol('PsLookupProcessByProcessId', hooks.HookPsLookupProcessByProcessId(cc=globals.mycc))
    globals.proj.hook_symbol('ObOpenObjectByPointer', hooks.HookObOpenObjectByPointer(cc=globals.mycc))
    globals.proj.hook_symbol('ZwDeleteFile', hooks.HookZwDeleteFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwOpenFile', hooks.HookZwOpenFile(cc=globals.mycc))
    globals.proj.hook_symbol('ZwCreateFile', hooks.HookZwCreateFile(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFile', hooks.HookIoCreateFile(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFileEx', hooks.HookIoCreateFileEx(cc=globals.mycc))
    globals.proj.hook_symbol('IoCreateFileSpecifyDeviceObjectHint',
                             hooks.HookIoCreateFileSpecifyDeviceObjectHint(cc=globals.mycc))
    globals.proj.hook_symbol('ExFreePoolWithTag', hooks.HookFreePoolWithTag(cc=globals.mycc))
    globals.proj.hook_symbol('SkAllocatePool', hooks.HookSkAllocatePool(cc=globals.mycc))
    globals.proj.hook_symbol('SkIsSecureKernel', hooks.HookSkIsSecureKernel(cc=globals.mycc))
    globals.proj.hook_symbol('SkFreePool', hooks.HookSkFreePool(cc=globals.mycc))

    globals.proj.hook_symbol('RtlAppendUnicodeStringToString',
                             hooks.HookRtlAppendUnicodeStringToString(cc=globals.mycc))
    globals.proj.hook_symbol('RtlNtStatusToDosErrorNoTeb', hooks.HookRtlNtStatusToDosErrorNoTeb(cc=globals.mycc))
    globals.proj.hook_symbol('ObReferenceObjectByHandle', hooks.HookObReferenceObjectByHandle(cc=globals.mycc))
    globals.proj.hook_symbol('ObfDereferenceObject', hooks.HookObfDereferenceObject(cc=globals.mycc))
    globals.proj.hook_symbol('ZwClose', hooks.HookZwClose(cc=globals.mycc))
    globals.proj.hook_symbol('KeEnterCriticalRegion', hooks.HookKeEnterCriticalRegion(cc=globals.mycc))
    globals.proj.hook_symbol('KeLeaveCriticalRegion', hooks.HookKeLeaveCriticalRegion(cc=globals.mycc))
    globals.proj.hook_symbol('ExAcquireResourceExclusiveLite',
                             hooks.HookExAcquireResourceExclusiveLite(cc=globals.mycc))

    hooks.find_targets(globals.driver_path)

    # Hook indirect jump.
    for indirect_jump in globals.cfg.indirect_jumps:
        indirect_jum_ins_addr = globals.cfg.indirect_jumps[indirect_jump].ins_addr
        if len(globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns):
            op = globals.proj.factory.block(indirect_jum_ins_addr).capstone.insns[0].op_str
            if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
                logger.debug(f'indirect jmp {hex(globals.cfg.indirect_jumps[indirect_jump].ins_addr)}')
                globals.proj.hook(globals.cfg.indirect_jumps[indirect_jump].ins_addr, opcodes.indirect_jmp_hook, 0)


def inspect_new_constraint(state):
    logger.debug(f'new constraint {state.inspect.added_constraints}')


def angr_enum_functions(proj):
    for addr in proj.kb.functions:
        logger.debug(f'function: {hex(addr)}')
        logger.debug(f'function name: {proj.kb.functions[addr].name}')
        logger.debug(f'strings: {list(proj.kb.functions[addr].string_references())}')


def rebased_addr(addr, ida_base):
    return addr - ida_base + globals.proj.loader.main_object.mapped_base


def set_hooks(proj):
    proj.hook_symbol('__stdio_common_vfprintf', hooks.stdio_common_vfprintf())
    proj.hook_symbol('__acrt_iob_func', hooks.acrt_iob_func())


def check_for_vulns(*args, **kwargs):
    sm = args[0]
    int_overflow.check_for_vulns(sm, globals.proj)
    """for state in sm.active:
        logger.debug(f'{state.addr} {state.regs.rip}')
        detect_overflow(state)
    """


def analyze(angr_proj):
    global state

    addr_target = 0x0000000140001000

    # Get control flow graph.
    globals.cfg = angr_proj.analyses.CFGFast()

    # Enumerate functions
    # angr_enum_functions(angr_proj)

    # Set hooks
    set_hooks(angr_proj)

    # Create a new state with the function arguments set up
    state = angr_proj.factory.blank_state()

    # Manually create a symbolic buffer
    input_buf_len = state.solver.BVV(0x10, 64)  # Example length for InputBufLen
    input_buffer = state.solver.BVS('input_buffer', 0x10 * 8)  # Create a symbolic bitvector for the buffer

    # Allocate memory for the buffer and store the symbolic buffer in memory
    input_buffer_addr = state.solver.BVV(0x100000, 64)  # Example address to store the buffer
    state.memory.store(input_buffer_addr, input_buffer)

    globals.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    # init_analysis(angr_proj)

    state = angr_proj.factory.call_state(
        addr_target,
        input_buffer_addr,
        input_buf_len,
        cc=globals.mycc,
        prototype="void call_me(char *InputBuffer, int64_t InputBufLen);"
    )

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
    # state.options.add(angr.options.SYMBOLIC_TEMPS)
    state.inspect.b('call', when=angr.BP_BEFORE, action=inspect_call)
    state.register_plugin("deep", SimStateDeepGlobals())

    # state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    globals.simgr = angr_proj.factory.simgr(state)
    # globals.simgr.use_technique(
    #    angr.exploration_techniques.LoopSeer(cfg=globals.cfg, functions=None, bound=globals.args.bound))
    # globals.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=globals.args.bound))

    # globals.simgr.use_technique(angr.exploration_techniques.LengthLimiter(globals.args.length))
    # globals.simgr.use_technique(angr.exploration_techniques.
    # globals.simgr.step()
    logger.debug(globals.simgr.active[0].regs.rip)
    globals.phase = 2

    globals.simgr.explore(find=[0x000000014000109D],
                          step_func=check_for_vulns,
                          )

    # IPython.embed()

    s = globals.simgr
    logger.debug(f'active: {len(s.active)}')
    logger.debug(f'found: {len(s.found)}')
    logger.debug(f'avoid: {len(s.avoid)}')
    logger.debug(f'deadended: {len(s.deadended)}')
    logger.debug(f'errored: {len(s.errored)}')
    logger.debug(f'unsat: {len(s.unsat)}')
    logger.debug(f'uncons: {len(s.unconstrained)}')

    logger.debug("Done")
    if len(s.found) > 0:

        found = s.one_found
        logger.debug("Found state")
    else:
        logger.debug("No found state")


def main():
    globals.driver_path = sys.argv[1]

    try:
        globals.proj = angr.Project(globals.driver_path, auto_load_libs=False)
        logger.debug(f'analyze driver {globals.driver_path}')
    except:
        logger.error(f'cannot analyze {globals.driver_path}')
        sys.exit(-1)
    analyze(globals.proj)


if __name__ == "__main__":
    main()
