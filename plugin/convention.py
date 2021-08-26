from binaryninja import CallingConvention

class vmquack_calling_convention(CallingConvention):
    name = "vmquack"
    callee_saved_regs = ('RBX', 'RSP', 'RBP', 'R12', 'R13', 'R14', 'R15')
    caller_saved_regs = (
        'RDI',
        'RSI',
        'RAX', 
        'RCX',
        'RDX',
        'R8',
        'R9',
        'R10',
        'R11',)

    int_return_reg = 'RAX'
    int_arg_regs = ('RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9')

class vmquack_syscall_convention(CallingConvention):
    name = "vmquack_syscall"
    int_return_reg = 'RAX'
    int_arg_regs = ('RAX', 'RDI', 'RSI', 'RDX', 'R10', 'R9', 'R8')
