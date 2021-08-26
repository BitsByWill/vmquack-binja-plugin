import binaryninja
from binaryninja import CallingConvention
from binaryninja.architecture import Architecture

from .vm import vmquack
from .view import vmquack_view
from .convention import vmquack_calling_convention, vmquack_syscall_convention

vmquack.register()
vm = binaryninja.architecture.Architecture['vmquack']
# vm.register_calling_convention(vmquack_calling_convention(vm, 'default'))
# vm.register_calling_convention(vmquack_syscall_convention(vm, 'syscall'))
vm.standalone_platform.default_calling_convention = vmquack_calling_convention(
    vm, 'default')
vm.standalone_platform.system_call_convention = vmquack_syscall_convention(
    vm, 'syscall')
vmquack_view.register()

# file format
# VMQUACK[8 bytes for data start][8 byte for length][8byte for text start][8 byte for length]