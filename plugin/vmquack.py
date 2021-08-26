BYTE, WORD, DWORD, QWORD = 0, 1, 2, 3
IMM, REG, MEM = 0, 1, 2

OPS = {
    0: "HLT",
    1: "SYSCALL",
    2: "CALL",
    3: "EXTERN_CALL",
    4: "RET",
    5: "PUSH",
    6: "POP",
    7: "JMP",
    8: "JE",
    9: "JNE",
    10: "JS",
    11: "JNS",
    12: "JG",
    13: "JL",
    14: "ADD",
    15: "SUB",
    16: "MUL",
    17: "IMUL",
    18: "DIV",
    19: "IDIV",
    20: "OR",
    21: "AND",
    22: "XOR",
    23: "SHL",
    24: "SHR",
    25: "NOT",
    26: "NEG",
    27: "INC",
    28: "DEC",
    29: "CMP",
    30: "MOV",
    31: "LEA",
    32: "NOP",
}

SINGLE_OPERANDS = {
    'PUSH', 'POP', 'MUL', 'IMUL', 'DIV', 'IDIV', 'NOT', 'NEG', 'INC', 'DEC'
}
BRANCH_OPCODES = {'CALL', 'JMP', 'JE', 'JNE', 'JS', 'JNS', 'JG', 'JL'}
SPECIAL_OPERANDS = {'EXTERN_CALL'}
SHIFT_OPERANDS = {'SHL', 'SHR'}
NO_OPERANDS = {'NOP', 'HLT', 'RET', 'SYSCALL'}

REGISTERS = [
    'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'R8', 'R9', 'R10', 'R11', 'R12',
    'R13', 'R14', 'R15', 'RBP', 'RSP', 'RFLAGS'
]
get_regs = lambda offset: REGISTERS[offset]

bt = lambda x, n: (x & (1 << n))

SUB_REGS = {
    "RAX": ["RAX", "EAX", "AX", "AL"],
    "RBX": ["RBX", "EBX", "BX", "BL"],
    "RCX": ["RCX", "ECX", "CX", "CL"],
    "RDX": ["RDX", "EDX", "DX", "DL"],
    "RSI": ["RSI", "ESI", "SI", "SIL"],
    "RDI": ["RDI", "EDI", "DI", "DIL"],
    "R8": ["R8", "R8D", "R8W", "R8B"],
    "R9": ["R9", "R9D", "R9W", "R9B"],
    "R10": ["R10", "R10D", "R10W", "R10B"],
    "R11": ["R11", "R11D", "R11W", "R11B"],
    "R12": ["R12", "R12D", "R12W", "R12B"],
    "R13": ["R13", "R13D", "R13W", "R13B"],
    "R14": ["R14", "R14D", "R14W", "R14B"],
    "R15": ["R15", "R15D", "R15W", "R15B"],
}

LOOKUP_PARENT_REG = {}
for k in SUB_REGS.keys():
    for v in SUB_REGS[k]:
        LOOKUP_PARENT_REG.update({v: k})


def get_parent_reg(reg):
    if reg in LOOKUP_PARENT_REG.keys():
        return LOOKUP_PARENT_REG[reg]
    else:
        return reg


def get_sub_regs(reg, datatype):
    idx = 0 if datatype == QWORD else 1 if datatype == DWORD else 2 if datatype == WORD else 3
    if reg in SUB_REGS.keys():
        return SUB_REGS[reg][idx]
    else:
        return reg


def get_data_str(d):
    if d == BYTE:
        return 'BYTE'
    elif d == WORD:
        return 'WORD'
    elif d == DWORD:
        return 'DWORD'
    else:
        return 'QWORD'


def get_datatype(c):
    if bt(c, 5):
        return BYTE
    elif bt(c, 6):
        return WORD
    elif bt(c, 7):
        return DWORD
    else:
        return QWORD


def get_src_operand(c):
    if bt(c, 0):
        return IMM
    elif bt(c, 1):
        return REG
    elif bt(c, 2):
        return MEM
    else:
        raise Exception('Invalid Source Operand')


def get_dest_operand(c):
    if bt(c, 3):
        return REG
    elif bt(c, 4):
        return MEM
    else:
        raise Exception('Invalid Dest Operand')