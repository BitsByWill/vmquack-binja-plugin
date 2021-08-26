from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, FlagRole, LowLevelILFlagCondition

from .instr import disas, gen_instr_il


class vmquack(Architecture):
    name = 'vmquack'
    address_size = 8
    instr_alignment = 1
    default_int_size = 4
    max_instr_length = 11

    regs = {
		'RAX': RegisterInfo('RAX', 8),
        'EAX': RegisterInfo('RAX', 4, 0),
        'AX': RegisterInfo('RAX', 2, 0),
        'AL': RegisterInfo('RAX', 1, 0),
        'RBX': RegisterInfo('RBX', 8),
        'EBX': RegisterInfo('RBX', 4, 0),
        'BX': RegisterInfo('RBX', 2, 0),
        'BL': RegisterInfo('RBX', 1, 0),
        'RCX': RegisterInfo('RCX', 8),
        'ECX': RegisterInfo('RCX', 4, 0),
        'CX': RegisterInfo('RCX', 2, 0),
        'CL': RegisterInfo('RCX', 1, 0),
        'RDX': RegisterInfo('RDX', 8),
        'EDX': RegisterInfo('RDX', 4, 0),
        'DX': RegisterInfo('RDX', 2, 0),
        'DL': RegisterInfo('RDX', 1, 0),
        'RSI': RegisterInfo('RSI', 8),
        'ESI': RegisterInfo('RSI', 4, 0),
        'SI': RegisterInfo('RSI', 2, 0),
        'SIL': RegisterInfo('RSI', 1, 0),
        'RDI': RegisterInfo('RDI', 8),
        'EDI': RegisterInfo('RDI', 4, 0),
        'DI': RegisterInfo('RDI', 2, 0),
        'DIL': RegisterInfo('RDI', 1, 0),
        'R8': RegisterInfo('R8', 8),
        'R8D': RegisterInfo('R8', 4, 0),
        'R8W': RegisterInfo('R8', 2, 0),
        'R8B': RegisterInfo('R8', 1, 0),
        'R9': RegisterInfo('R9', 8),
        'R9D': RegisterInfo('R9', 4, 0),
        'R9W': RegisterInfo('R9', 2, 0),
        'R9B': RegisterInfo('R9', 1, 0),
        'R10': RegisterInfo('R10', 8),
        'R10D': RegisterInfo('R10', 4, 0),
        'R10W': RegisterInfo('R10', 2, 0),
        'R10B': RegisterInfo('R10', 1, 0),
        'R11': RegisterInfo('R11', 8),
        'R11D': RegisterInfo('R11', 4, 0),
        'R11W': RegisterInfo('R11', 2, 0),
        'R11B': RegisterInfo('R11', 1, 0),
        'R12': RegisterInfo('R12', 8),
        'R12D': RegisterInfo('R12', 4, 0),
        'R12W': RegisterInfo('R12', 2, 0),
        'R12B': RegisterInfo('R12', 1, 0),
        'R13': RegisterInfo('R13', 8),
        'R13D': RegisterInfo('R13', 4, 0),
        'R13W': RegisterInfo('R13', 2, 0),
        'R13B': RegisterInfo('R13', 1, 0),
        'R14': RegisterInfo('R14', 8),
        'R14D': RegisterInfo('R14', 4, 0),
        'R14W': RegisterInfo('R14', 2, 0),
        'R14B': RegisterInfo('R14', 1, 0),
        'R15': RegisterInfo('R15', 8),
        'R15D': RegisterInfo('R15', 4, 0),
        'R15W': RegisterInfo('R15', 2, 0),
        'R15B': RegisterInfo('R15', 1, 0),
        'RBP': RegisterInfo('RBP', 8),
        'RSP': RegisterInfo('RSP', 8),
        'RFLAGS': RegisterInfo('RFLAGS', 8),
    }
    stack_pointer = 'RSP'

    flags = ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of']

    flag_roles = {
        'cf': FlagRole.CarryFlagRole,
        'pf': FlagRole.EvenParityFlagRole,
        'af': FlagRole.CarryFlagRole,
        'zf': FlagRole.ZeroFlagRole,
        'sf': FlagRole.NegativeSignFlagRole,
        'tf': FlagRole.SpecialFlagRole,
        'df': FlagRole.SpecialFlagRole,
        'of': FlagRole.OverflowFlagRole
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGE: ["cf"],
        LowLevelILFlagCondition.LLFC_ULE: ["cf"],
        LowLevelILFlagCondition.LLFC_UGT: ["cf", "zf"],
        LowLevelILFlagCondition.LLFC_ULT: ["cf", "zf"],
        LowLevelILFlagCondition.LLFC_SGE: ["zf", "sf", "of"],
        LowLevelILFlagCondition.LLFC_SLE: ["zf", "sf", "of"],
        LowLevelILFlagCondition.LLFC_SGT: ["sf", "of"],
        LowLevelILFlagCondition.LLFC_SLT: ["sf", "of"],
        LowLevelILFlagCondition.LLFC_E: ["zf"],
        LowLevelILFlagCondition.LLFC_NE: ["zf"],
    }

    '''
    So for any instructions that are not ADD, ADC, SUB, NEG, or FSUB, 
    you can try and see if Binja's built-in for calculating negative, positive, or zero flags are accurate for your architecture.
    If you want carry, ordered, overflow, or unordered, you will need to implement it yourself.
    get_flag_write_low_level_il -> override flag behavior for specific opcodes
    '''
    flag_write_types = ['*', "zc", "zs", "c", "zso", "zsco", "zsc"]

    flags_written_by_flag_write_type = {
        "*": ["cf", "pf", "af", "zf", "sf", "of"],
        "zc": ["cf", "zf"],
        "zs": ["zf", "sf"],
        "zso": ["zf", "sf", "of"],
        "c": ["cf"],
        "zsco": ["zf", "sf", "of", "cf"],
        "zsc": ["zf", "sf", "cf"]
    }

    def get_instruction_info(self, data, addr):
        result = disas(data, addr)
        if result is None:
            return None
        return result[1]

    def get_instruction_text(self, data, addr):
        result = disas(data, addr)
        if result is None:
            return None
        return result[0], result[1].length

    def get_instruction_low_level_il(self, data, addr, il):
        result = disas(data, addr)
        if result is None:
            return None
        asm, info, instruction = result
        gen_instr_il(addr, instruction, il)
        return result[1].length
