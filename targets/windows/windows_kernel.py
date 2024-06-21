import hooks
import shared
import utils
from helpers.log import logger

def next_base_addr(size=0x10000):
    v = shared.FIRST_ADDR
    shared.FIRST_ADDR += size
    return v


def init_analysis(angr_proj):
    logger.debug('init analysis')
    shared.DO_NOTHING = next_base_addr()
    shared.proj.hook(shared.DO_NOTHING, hooks.HookDoNothing(cc=shared.mycc))

    # Hook target kernel APIs.
    hooks.find_hook_func()
    shared.DO_NOTHING = utils.next_base_addr()
    shared.proj.hook(shared.DO_NOTHING, hooks.HookDoNothing(cc=shared.mycc))
    shared.proj.hook_symbol('memmove', hooks.HookMemcpy(cc=shared.mycc))
    shared.proj.hook_symbol('memcpy', hooks.HookMemcpy(cc=shared.mycc))
    shared.proj.hook_symbol('ZwOpenSection', hooks.HookZwOpenSection(cc=shared.mycc))
    shared.proj.hook_symbol('RtlInitUnicodeString', hooks.HookRtlInitUnicodeString(cc=shared.mycc))
    shared.proj.hook_symbol('RtlCopyUnicodeString', hooks.HookRtlCopyUnicodeString(cc=shared.mycc))
    """    shared.proj.hook_symbol('IoStartPacket', hooks.HookIoStartPacket(cc=shared.mycc))
    shared.proj.hook_symbol('IoCreateDevice', hooks.HookIoCreateDevice(cc=shared.mycc))
    shared.proj.hook_symbol('IoCreateSymbolicLink', hooks.HookIoCreateSymbolicLink(cc=shared.mycc))"""
    shared.proj.hook_symbol('IoIs32bitProcess', hooks.HookIoIs32bitProcess(cc=shared.mycc))
    shared.proj.hook_symbol('RtlGetVersion', hooks.HookRtlGetVersion(cc=shared.mycc))
    shared.proj.hook_symbol('ExGetPreviousMode', hooks.HookExGetPreviousMode(cc=shared.mycc))
    shared.proj.hook_symbol('KeQueryActiveGroupCount', hooks.HookKeQueryActiveGroupCount(cc=shared.mycc))
    shared.proj.hook_symbol('KeQueryActiveProcessors', hooks.HookKeQueryActiveProcessors(cc=shared.mycc))
    shared.proj.hook_symbol('KeQueryActiveProcessorCountEx', hooks.HookKeQueryActiveProcessorCountEx(cc=shared.mycc))
    shared.proj.hook_symbol('ExInterlockedPopEntrySList', hooks.HookExInterlockedPopEntrySList(cc=shared.mycc))
    shared.proj.hook_symbol('ExQueryDepthSList', hooks.HookExQueryDepthSList(cc=shared.mycc))
    shared.proj.hook_symbol('ExpInterlockedPushEntrySList', hooks.HookExpInterlockedPushEntrySList(cc=shared.mycc))
    shared.proj.hook_symbol('ExpInterlockedPopEntrySList', hooks.HookExpInterlockedPopEntrySList(cc=shared.mycc))
    shared.proj.hook_symbol('PsGetVersion', hooks.HookPsGetVersion(cc=shared.mycc))
    shared.proj.hook_symbol('ExInitializeResourceLite', hooks.HookExInitializeResourceLite(cc=shared.mycc))
    shared.proj.hook_symbol('KeWaitForSingleObject', hooks.HookKeWaitForSingleObject(cc=shared.mycc))
    shared.proj.hook_symbol('RtlWriteRegistryValue', hooks.HookRtlWriteRegistryValue(cc=shared.mycc))
    shared.proj.hook_symbol('IoGetDeviceProperty', hooks.HookIoGetDeviceProperty(cc=shared.mycc))
    shared.proj.hook_symbol('KeReleaseMutex', hooks.HookKeReleaseMutex(cc=shared.mycc))
    shared.proj.hook_symbol('MmGetSystemRoutineAddress', hooks.HookMmGetSystemRoutineAddress(cc=shared.mycc))
    shared.proj.hook_symbol('FltGetRoutineAddress', hooks.HookFltGetRoutineAddress(cc=shared.mycc))
    shared.proj.hook_symbol('RtlGetElementGenericTable', hooks.HookDoNothing(cc=shared.mycc))
    shared.proj.hook_symbol('ExAcquireResourceExclusiveLite', hooks.HookDoNothing(cc=shared.mycc))
    shared.proj.hook_symbol('ProbeForRead', hooks.HookProbeForRead(cc=shared.mycc))
    shared.proj.hook_symbol('ProbeForWrite', hooks.HookProbeForWrite(cc=shared.mycc))
    shared.proj.hook_symbol('MmIsAddressValid', hooks.HookMmIsAddressValid(cc=shared.mycc))
    shared.proj.hook_symbol('ZwQueryInformationFile', hooks.HookZwQueryInformationFile(cc=shared.mycc))
    shared.proj.hook_symbol('ZwQueryInformationProcess', hooks.HookZwQueryInformationProcess(cc=shared.mycc))
    shared.proj.hook_symbol("ObReferenceObjectByHandle", hooks.HookObReferenceObjectByHandle(cc=shared.mycc))
    shared.proj.hook_symbol("ZwWriteFile", hooks.HookZwWriteFile(cc=shared.mycc))
    shared.proj.hook_symbol("ZwCreateKey", hooks.HookZwCreateKey(cc=shared.mycc))
    shared.proj.hook_symbol("ZwOpenKey", hooks.HookZwOpenKey(cc=shared.mycc))
    shared.proj.hook_symbol("ZwDeleteValueKey", hooks.HookZwDeleteValueKey(cc=shared.mycc))
    shared.proj.hook_symbol("ZwQueryValueKey", hooks.HookZwQueryValueKey(cc=shared.mycc))
    shared.proj.hook_symbol("NdisRegisterProtocolDriver", hooks.HookNdisRegisterProtocolDriver(cc=shared.mycc))

    # Only hook for phase 2 to hunt vulnerabilities.
    shared.proj.hook_symbol("ExAllocatePool", hooks.HookExAllocatePool(cc=shared.mycc))
    shared.proj.hook_symbol("ExAllocatePool2", angr.procedures.SIM_PROCEDURES['libc']['malloc'](cc=shared.mycc))
    shared.proj.hook_symbol("ExAllocatePool3", hooks.HookExAllocatePool3(cc=shared.mycc))
    shared.proj.hook_symbol("MmAllocateNonCachedMemory", hooks.HookMmAllocateNonCachedMemory(cc=shared.mycc))
    shared.proj.hook_symbol("ExAllocatePoolWithTag", hooks.HookExAllocatePoolWithTag(cc=shared.mycc))
    shared.proj.hook_symbol("MmAllocateContiguousMemorySpecifyCache",
                             hooks.HookMmAllocateContiguousMemorySpecifyCache(cc=shared.mycc))
    shared.proj.hook_symbol('MmMapIoSpace', hooks.HookMmMapIoSpace(cc=shared.mycc))
    shared.proj.hook_symbol('MmMapIoSpaceEx', hooks.HookMmMapIoSpaceEx(cc=shared.mycc))
    shared.proj.hook_symbol('HalTranslateBusAddress', hooks.HookHalTranslateBusAddress(cc=shared.mycc))
    shared.proj.hook_symbol('ZwMapViewOfSection', hooks.HookZwMapViewOfSection(cc=shared.mycc))
    shared.proj.hook_symbol('ZwOpenProcess', hooks.HookZwOpenProcess(cc=shared.mycc))
    shared.proj.hook_symbol('PsLookupProcessByProcessId', hooks.HookPsLookupProcessByProcessId(cc=shared.mycc))
    shared.proj.hook_symbol('ObOpenObjectByPointer', hooks.HookObOpenObjectByPointer(cc=shared.mycc))
    shared.proj.hook_symbol('ZwDeleteFile', hooks.HookZwDeleteFile(cc=shared.mycc))
    shared.proj.hook_symbol('ZwOpenFile', hooks.HookZwOpenFile(cc=shared.mycc))
    shared.proj.hook_symbol('ZwCreateFile', hooks.HookZwCreateFile(cc=shared.mycc))
    shared.proj.hook_symbol('IoCreateFile', hooks.HookIoCreateFile(cc=shared.mycc))
    shared.proj.hook_symbol('IoCreateFileEx', hooks.HookIoCreateFileEx(cc=shared.mycc))
    shared.proj.hook_symbol('IoCreateFileSpecifyDeviceObjectHint',
                             hooks.HookIoCreateFileSpecifyDeviceObjectHint(cc=shared.mycc))
    shared.proj.hook_symbol('ExFreePoolWithTag', hooks.HookFreePoolWithTag(cc=shared.mycc))
    shared.proj.hook_symbol('SkAllocatePool', hooks.HookSkAllocatePool(cc=shared.mycc))
    shared.proj.hook_symbol('SkIsSecureKernel', hooks.HookSkIsSecureKernel(cc=shared.mycc))
    shared.proj.hook_symbol('SkFreePool', hooks.HookSkFreePool(cc=shared.mycc))

    shared.proj.hook_symbol('RtlAppendUnicodeStringToString',
                             hooks.HookRtlAppendUnicodeStringToString(cc=shared.mycc))
    shared.proj.hook_symbol('RtlNtStatusToDosErrorNoTeb', hooks.HookRtlNtStatusToDosErrorNoTeb(cc=shared.mycc))
    shared.proj.hook_symbol('ObReferenceObjectByHandle', hooks.HookObReferenceObjectByHandle(cc=shared.mycc))
    shared.proj.hook_symbol('ObfDereferenceObject', hooks.HookObfDereferenceObject(cc=shared.mycc))
    shared.proj.hook_symbol('ZwClose', hooks.HookZwClose(cc=shared.mycc))
    shared.proj.hook_symbol('KeEnterCriticalRegion', hooks.HookKeEnterCriticalRegion(cc=shared.mycc))
    shared.proj.hook_symbol('KeLeaveCriticalRegion', hooks.HookKeLeaveCriticalRegion(cc=shared.mycc))
    shared.proj.hook_symbol('ExAcquireResourceExclusiveLite',
                             hooks.HookExAcquireResourceExclusiveLite(cc=shared.mycc))

    hooks.find_targets(shared.driver_path)

    # Hook indirect jump.
    for indirect_jump in shared.cfg.indirect_jumps:
        indirect_jum_ins_addr = shared.cfg.indirect_jumps[indirect_jump].ins_addr
        if len(shared.proj.factory.block(indirect_jum_ins_addr).capstone.insns):
            op = shared.proj.factory.block(indirect_jum_ins_addr).capstone.insns[0].op_str
            if op == 'rax' or op == 'rbx' or op == 'rcx' or op == 'rdx':
                logger.debug(f'indirect jmp {hex(shared.cfg.indirect_jumps[indirect_jump].ins_addr)}')
                shared.proj.hook(shared.cfg.indirect_jumps[indirect_jump].ins_addr, opcodes.indirect_jmp_hook, 0)
