from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, LowLevelILOperation, LowLevelILFlagCondition
from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILFunction
from struct import unpack
from .vmquack import *
import ctypes


def sign8(val):
    return ctypes.c_byte(val).value


def sign32(val):
    return ctypes.c_int(val).value


def u8(val):
    return ord(val)


def u16(val):
    value = unpack('H', val)[0]
    return value


def u32(val):
    value = unpack('I', val)[0]
    return value


def u64(val):
    value = unpack('Q', val)[0]
    return value


tI = lambda x: InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
tR = lambda x: InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
tS = lambda x: InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
tBM = lambda x: InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
tEM = lambda x: InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
tA = lambda x, d: InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
tT = lambda x: InstructionTextToken(InstructionTextTokenType.TextToken, x)
tN = lambda x, d: InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)


def check(result):
    if not result:
        raise Exception('ERROR')
    return


class Instr:
    def __init__(self):
        self.opcode = None  # opcode (make only opcode, registers, and data type strings)
        self.data_type = None  # byte, word, dword, qword
        self.mode1 = None  # imm, reg, mem, for whatever is in front
        self.mode2 = None  # imm, reg, mem
        self.is_single = None
        self.dest_reg = None  # first operand for both reg and mem, use this if only one operand
        self.src_reg = None  # second possible operand for both reg and mem
        self.imm_value = None  # generic imm value
        self.special_val = None  # for extern_calls
        self.is_shift = None  # for shift operands
        self.length = None  # instruction length
        self.addr = None

    def generate_text(self, code):
        check(self.opcode is not None)
        if self.opcode in NO_OPERANDS:
            code.append(tI(self.opcode))
            return
        if self.opcode in SPECIAL_OPERANDS:
            code.append(tI(self.opcode))
            # print('%s %d' % (self.opcode, self.length))
            check(self.special_val is not None)
            code.append(tS(' '))
            code.append(tN(hex(self.special_val), self.special_val))
            return
        if self.opcode in SHIFT_OPERANDS:
            check(self.data_type is not None and self.dest_reg is not None)
            code.append(tI(self.opcode))
            code.append(tS(' '))
            code.append(tS(get_data_str(self.data_type)))
            code.append(tS(' '))
            check(self.mode1 == REG or self.mode1 == MEM)
            if self.mode1 == REG:
                code.append(tR(self.dest_reg))
            else:
                code.append(tBM('['))
                code.append(tR(self.dest_reg))
                code.append(tEM(']'))
            code.append(tS(', '))
            code.append(tN(hex(self.imm_value), self.imm_value))
            return
        # most other instructions now
        check(self.mode1 in [IMM, REG, MEM]
              and self.data_type in [BYTE, WORD, DWORD, QWORD])
        code.append(tI(self.opcode))
        code.append(tS(' '))
        code.append(tS(get_data_str(self.data_type)))
        code.append(tS(' '))
        if self.mode1 == IMM:
            check(self.imm_value is not None)
            check(self.opcode in SINGLE_OPERANDS
                  or self.opcode in BRANCH_OPCODES)  # otherwise not possible
            if self.opcode not in BRANCH_OPCODES:
                code.append(tN(hex(self.imm_value), self.imm_value))
            else:  # convert jumps to absolute so we can read it in disas sensably lol
                check(self.data_type in [BYTE, DWORD])
                if self.data_type == BYTE:
                    code.append(
                        tN(
                            hex(
                                sign8(self.imm_value) + self.length +
                                self.addr),
                            sign8(self.imm_value) + self.length + self.addr))
                else:
                    code.append(
                        tN(
                            hex(
                                sign32(self.imm_value) + self.length +
                                self.addr),
                            sign32(self.imm_value) + self.length + self.addr))
            return  # has to return now
        check(self.is_single is not None)
        if not self.is_single:
            check(self.mode2 is not None)
        check(self.dest_reg is not None)
        if self.mode1 == REG:
            code.append(tR(self.dest_reg))
        else:
            code.append(tBM('['))
            code.append(tR(self.dest_reg))
            code.append(tEM(']'))
        if self.is_single:
            return
            # has two operands now
        check(self.mode2 in [IMM, REG, MEM])
        code.append(tS(', '))
        if self.mode2 == IMM:
            check(self.imm_value is not None)
            code.append(tN(hex(self.imm_value), self.imm_value))
            return
        elif self.mode2 == REG:
            check(self.src_reg is not None)
            code.append(tR(self.src_reg))
            return
        elif self.mode2 == MEM:
            check(self.src_reg is not None)
            code.append(tBM('['))
            code.append(tR(self.dest_reg))
            code.append(tEM(']'))
            return
        else:
            raise Exception('Error in generating two operand instructions')

    def get_size(self):
        return 1 if self.data_type == BYTE else 2 if self.data_type == WORD else 4 if self.data_type == DWORD else 8


def build_flow(info, instruction, addr):
    if instruction.opcode not in BRANCH_OPCODES and instruction.opcode not in [
            'RET', 'HLT', 'SYSCALL', 'EXTERN_CALL'
    ]:
        return
    if instruction.opcode == 'SYSCALL' or instruction.opcode == 'EXTERN_CALL':
        info.add_branch(BranchType.SystemCall)
        return
    if instruction.opcode == 'RET' or instruction.opcode == 'HLT':
        info.add_branch(BranchType.UnconditionalBranch)
        return
    if instruction.mode1 != IMM:
        info.add_branch(BranchType.UnresolvedBranch)
        return
    # for IMM jumps and calls
    if instruction.opcode == 'JMP':
        if instruction.data_type == BYTE:
            info.add_branch(BranchType.UnconditionalBranch,
                            sign8(instruction.imm_value) + addr + info.length)
        else:
            info.add_branch(BranchType.UnconditionalBranch,
                            sign32(instruction.imm_value) + addr + info.length)
        return
    if instruction.opcode == 'CALL':
        if instruction.data_type == BYTE:
            info.add_branch(BranchType.CallDestination,
                            sign8(instruction.imm_value) + addr + info.length)
        else:
            info.add_branch(BranchType.CallDestination,
                            sign32(instruction.imm_value) + addr + info.length)
        return
    if instruction.data_type == BYTE:
        info.add_branch(BranchType.TrueBranch,
                        sign8(instruction.imm_value) + addr + info.length)
    elif instruction.data_type == DWORD:
        info.add_branch(BranchType.TrueBranch,
                        sign32(instruction.imm_value) + addr + info.length)
    else:
        raise Exception("Invalid Branch Data Type")
    info.add_branch(BranchType.FalseBranch, addr + info.length)
    return


def disas(data, addr):  # handle disas, also return in good instruction format, and handle branching/code flow
    instruction = Instr()  # for handling and storing stuff to build and append data to
    code = []
    info = InstructionInfo()
    i = 0
    try:
        if data[i] not in OPS:
            return None
        if OPS[data[i]] in NO_OPERANDS:  # no operand instructions
            instruction.addr = addr
            instruction.opcode = OPS[data[i]]
            i += 1
        elif OPS[data[i]] in SPECIAL_OPERANDS:  # extern_call
            instruction.addr = addr
            instruction.opcode = OPS[data[i]]
            i += 1
            instruction.special_val = data[i]
            i += 1
        elif OPS[data[i]] in SHIFT_OPERANDS:
            instruction.addr = addr
            instruction.opcode = OPS[data[i]]
            instruction.is_shift = True
            i += 1
            instruction.data_type = get_datatype(data[i])
            instruction.mode2 = IMM
            instruction.mode1 = get_dest_operand(data[i])
            i += 1
            if instruction.mode1 == REG:
                instruction.dest_reg = get_sub_regs(get_regs(data[i]),
                                                    instruction.data_type)
            else:
                instruction.dest_reg = get_regs(data[i])
            i += 1
            instruction.imm_value = u8(bytes(data[i:i + 1]))
            i += 1
        else:
            instruction.addr = addr
            instruction.opcode = OPS[data[i]]
            instruction.is_single = True if OPS[
                data[i]] in SINGLE_OPERANDS or OPS[
                    data[i]] in BRANCH_OPCODES else False
            i += 1
            instruction.data_type = get_datatype(data[i])
            instruction.mode1 = get_src_operand(data[i])
            if not instruction.is_single:
                instruction.mode1 = get_dest_operand(data[i])
                instruction.mode2 = get_src_operand(data[i])
            i += 1
            if instruction.mode1 == IMM:
                if instruction.data_type == BYTE:
                    instruction.imm_value = u8(bytes(data[i:i + 1]))
                    i += 1
                elif instruction.data_type == WORD:
                    instruction.imm_value = u16(bytes(data[i:i + 2]))
                    i += 2
                elif instruction.data_type == DWORD:
                    instruction.imm_value = u32(bytes(data[i:i + 4]))
                    i += 4
                else:
                    instruction.imm_value = u64(bytes(data[i:i + 8]))
                    i += 8
            elif instruction.mode1 == REG or instruction.mode1 == MEM:
                if instruction.mode1 == REG:
                    instruction.dest_reg = get_sub_regs(
                        get_regs(data[i]), instruction.data_type)
                else:
                    instruction.dest_reg = get_regs(data[i])
                i += 1
                if not instruction.is_single:
                    if instruction.mode2 == IMM:
                        if instruction.data_type == BYTE:
                            instruction.imm_value = u8(bytes(data[i:i + 1]))
                            i += 1
                        elif instruction.data_type == WORD:
                            instruction.imm_value = u16(bytes(data[i:i + 2]))
                            i += 2
                        elif instruction.data_type == DWORD:
                            instruction.imm_value = u32(bytes(data[i:i + 4]))
                            i += 4
                        else:
                            instruction.imm_value = u64(bytes(data[i:i + 8]))
                            i += 8
                    elif instruction.mode2 == REG or instruction.mode2 == MEM:
                        if instruction.mode2 == REG:
                            instruction.src_reg = get_sub_regs(
                                get_regs(data[i]), instruction.data_type)
                        else:
                            instruction.src_reg = get_regs(data[i])
                        i += 1
                    else:
                        return None
            else:
                return None
        info.length = i
        instruction.length = info.length
        instruction.generate_text(code)
        build_flow(info, instruction, addr)
        return (code, info, instruction)
    except IndexError:
        return None


def operand_to_il(instruction, il, size=None, first=True, branch=False):
    if size is None:
        size = instruction.get_size()
        if size == 0:
            raise Exception('invalid size in il for instruction %s' %
                            instruction.opcode)
    if first:
        if instruction.mode1 == IMM:
            if not branch:
                return il.const(size, instruction.imm_value)
            else:
                if instruction.data_type == BYTE:
                    return il.const(
                        size,
                        sign8(instruction.imm_value) + instruction.addr +
                        instruction.length)
                elif instruction.data_type == DWORD:
                    return il.const(
                        size,
                        sign32(instruction.imm_value) + instruction.addr +
                        instruction.length)
                else:
                    return il.unimplemented()
        if instruction.mode1 == REG:
            return il.reg(size, instruction.dest_reg)
        if instruction.mode1 == MEM:
            part1 = il.reg(8, instruction.dest_reg)
            tmp_expr_1 = part1
            return il.load(size, tmp_expr_1)
    else:
        if instruction.mode2 == IMM:
            return il.const(size, instruction.imm_value)
        if instruction.mode2 == REG:
            return il.reg(size, instruction.src_reg)
        if instruction.mode2 == MEM:
            part1 = il.reg(8, instruction.src_reg)
            tmp_expr_1 = part1
            return il.load(size, tmp_expr_1)
    return il.unimplemented()


def store_result(instruction, tmp_expr, il, size=None):
    if size is None:
        size = instruction.get_size()
    if instruction.mode1 == REG:
        if instruction.data_type != DWORD:
            return il.set_reg(size, instruction.dest_reg, tmp_expr)
        else:
            return il.set_reg(8, get_parent_reg(instruction.dest_reg),
                              il.zero_extend(8, tmp_expr))
    elif instruction.mode1 == MEM:
        dest = il.reg(8, instruction.dest_reg)
        return il.store(size, dest, tmp_expr)
    else:
        return il.unimplemented()


def goto_or_jump(addr, instruction, il):
    if instruction.mode1 == IMM:
        dest = None
        if instruction.data_type == BYTE:
            dest = addr + instruction.length + sign8(instruction.imm_value)
        elif instruction.data_type == DWORD:
            dest = addr + instruction.length + sign32(instruction.imm_value)
        else:
            return il.unimplemented()
        tmp = il.get_label_for_address(Architecture['vmquack'], dest)
        if tmp:
            return il.goto(tmp)
        else:
            # if no label exists, create one
            tmp = LowLevelILLabel()
            il.mark_label(tmp)
            return il.jump(il.const_pointer(8, dest))
    else:
        return il.jump(operand_to_il(instruction, il))


def append_conditional_jmp(addr, instruction, il, conditional):
    if instruction.mode1 == IMM:
        dest = None
        if instruction.data_type == BYTE:
            dest = addr + instruction.length + sign8(instruction.imm_value)
        elif instruction.data_type == DWORD:
            dest = addr + instruction.length + sign32(instruction.imm_value)
        else:
            return il.unimplemented()
        t = il.get_label_for_address(
            Architecture['vmquack'],
            addr + instruction.length + instruction.imm_value)
        f = il.get_label_for_address(Architecture['vmquack'],
                                     addr + instruction.length)
        # if label is available
        if t and f:
            return il.if_expr(conditional, t, f)
        tmp = goto_or_jump(addr, instruction, il)
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(conditional, t, f))
        il.mark_label(t)  # mark t here
        il.append(tmp)
        il.mark_label(f)
        return il.nop()
    else:
        return il.unimplemented()


def gen_instr_il(addr, instruction, il):
    if instruction.opcode == "HLT":
        il.append(il.no_ret())
    elif instruction.opcode == "SYSCALL":
        il.append(il.system_call())
    elif instruction.opcode == "CALL":
        il.append(
            il.call_stack_adjust(operand_to_il(instruction, il, branch=True),
                                 8))
    elif instruction.opcode == "EXTERN_CALL":
        il.append(il.unimplemented())
    elif instruction.opcode == "RET":
        il.append(il.ret(il.load(8, il.reg(8, 'RSP'))))
    elif instruction.opcode == "PUSH":
        il.append(il.push(8, il.zero_extend(8, operand_to_il(instruction, il))))
    elif instruction.opcode == "POP":
        tmp = il.pop(8)
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "JMP":
        il.append(goto_or_jump(addr, instruction, il))
    elif instruction.opcode == "JE":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_E)))
    elif instruction.opcode == "JNE":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_NE)))
    elif instruction.opcode == "JS":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_NEG)))
    elif instruction.opcode == "JNS":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_POS)))
    elif instruction.opcode == "JG":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_UGT)))
    elif instruction.opcode == "JL":
        il.append(
            append_conditional_jmp(
                addr, instruction, il,
                il.flag_condition(LowLevelILFlagCondition.LLFC_ULT)))
    elif instruction.opcode == "ADD":
        tmp = il.add(instruction.get_size(),
                     operand_to_il(instruction, il),
                     operand_to_il(instruction, il, first=False),
                     flags="zsco")
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "SUB":
        tmp = il.sub(instruction.get_size(),
                     operand_to_il(instruction, il),
                     operand_to_il(instruction, il, first=False),
                     flags="zsco")
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "MUL":
        if instruction.data_type == BYTE:
            tmp0 = il.mult(2, il.reg(1, 'AL'), operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
        elif instruction.data_type == WORD:
            tmp0 = il.mult(4, il.reg(2, 'AX'), operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
            tmp1 = il.logical_shift_right(4, tmp0, il.const(1, 16))
            il.append(il.set_reg(2, 'DX', tmp1))
        elif instruction.data_type == DWORD:
            tmp0 = il.mult(8, il.reg(4, 'EAX'), operand_to_il(instruction, il))
            il.append(il.set_reg(4, 'EAX', tmp0))
            tmp1 = il.logical_shift_right(8, tmp0, il.const(1, 32))
            il.append(il.set_reg(4, 'EDX', tmp0))
        else:
            tmp0 = il.mult(16, il.reg(8, 'RAX'),
                           operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RAX', tmp0))
            tmp1 = il.logical_shift_right(16, tmp0, il.const(1, 64))
            il.append(il.set_reg(8, 'RDX', tmp1))
    elif instruction.opcode == "IMUL":
        if instruction.data_type == BYTE:
            tmp0 = il.mult(2, il.reg(1, 'AL'), operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
        elif instruction.data_type == WORD:
            tmp0 = il.mult(4, il.reg(2, 'AX'), operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
            tmp1 = il.logical_shift_right(4, tmp0, il.const(1, 16))
            il.append(il.set_reg(2, 'DX', tmp1))
        elif instruction.data_type == DWORD:
            tmp0 = il.mult(8, il.reg(4, 'EAX'), operand_to_il(instruction, il))
            il.append(il.set_reg(4, 'EAX', tmp0))
            tmp1 = il.logical_shift_right(8, tmp0, il.const(1, 32))
            il.append(il.set_reg(4, 'EDX', tmp0))
        else:
            tmp0 = il.mult(16, il.reg(8, 'RAX'),
                           operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RAX', tmp0))
            tmp1 = il.logical_shift_right(16, tmp0, il.const(1, 64))
            il.append(il.set_reg(8, 'RDX', tmp1))
    elif instruction.opcode == "DIV":
        if instruction.data_type == BYTE:
            tmp0 = il.div_unsigned(2, il.reg(2, 'AX'),
                                   operand_to_il(instruction, il))
            tmp1 = il.mod_unsigned(2, il.reg(2, 'AX'),
                                   operand_to_il(instruction, il))
            tmp1 = il.shift_left(2, tmp, il.const(1, 8))
            result = il.add(2, tmp0, tmp1)
            il.append(il.set_reg(2, 'AX', result))
        elif instruction.data_type == WORD:
            pair0 = il.reg(2, 'AX')
            pair1 = il.shift_left(4, il.reg(2, 'DX'), il.const(1, 16))
            dividend = il.add(4, pair0, pair1)
            tmp0 = il.div_unsigned(4, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
            tmp1 = il.mod_unsigned(4, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'DX', tmp1))
        elif instruction.data_type == DWORD:
            pair0 = il.reg(4, 'EAX')
            pair1 = il.shift_left(8, il.reg(4, 'EDX'), il.const(1, 32))
            dividend = il.add(8, pair0, pair1)
            tmp0 = il.div_unsigned(8, dividend, operand_to_il(instruction, il))
            il.append(il.zero_extend(8, il.set_reg(4, 'RAX', tmp0)))
            tmp1 = il.mod_unsigned(8, dividend, operand_to_il(instruction, il))
            il.append(il.zero_extend(8, il.set_reg(4, 'RDX', tmp1)))
        else:
            pair0 = il.reg(8, 'RAX')
            pair1 = il.shift_left(16, il.reg(4, 'RDX'), il.const(1, 64))
            dividend = il.add(16, pair0, pair1)
            tmp0 = il.div_unsigned(16, dividend,
                                   operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RAX', tmp0))
            tmp1 = il.mod_unsigned(16, dividend,
                                   operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RDX', tmp1))
    elif instruction.opcode == "IDIV":
        if instruction.data_type == BYTE:
            tmp0 = il.div_signed(2, il.reg(2, 'AX'),
                                 operand_to_il(instruction, il))
            tmp1 = il.mod_signed(2, il.reg(2, 'AX'),
                                 operand_to_il(instruction, il))
            tmp1 = il.shift_left(2, tmp, il.const(1, 8))
            result = il.add(2, tmp0, tmp1)
            il.append(il.set_reg(2, 'AX', result))
        elif instruction.data_type == WORD:
            pair0 = il.reg(2, 'AX')
            pair1 = il.shift_left(4, il.reg(2, 'DX'), il.const(1, 16))
            dividend = il.add(4, pair0, pair1)
            tmp0 = il.div_signed(4, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'AX', tmp0))
            tmp1 = il.mod_signed(4, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(2, 'DX', tmp1))
        elif instruction.data_type == DWORD:
            pair0 = il.reg(4, 'RAX')
            pair1 = il.shift_left(8, il.reg(4, 'RDX'), il.const(1, 32))
            dividend = il.add(8, pair0, pair1)
            tmp0 = il.div_signed(8, dividend, operand_to_il(instruction, il))
            il.append(il.zero_extend(8, il.set_reg(4, 'RAX', tmp0)))
            tmp1 = il.mod_signed(8, dividend, operand_to_il(instruction, il))
            il.append(il.zero_extend(8, il.set_reg(4, 'RDX', tmp1)))
        else:
            pair0 = il.reg(8, 'RAX')
            pair1 = il.shift_left(16, il.reg(4, 'RDX'), il.const(1, 64))
            dividend = il.add(16, pair0, pair1)
            tmp0 = il.div_signed(16, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RAX', tmp0))
            tmp1 = il.mod_signed(16, dividend, operand_to_il(instruction, il))
            il.append(il.set_reg(8, 'RDX', tmp1))
    elif instruction.opcode == "OR":
        tmp = il.or_expr(instruction.get_size(),
                         operand_to_il(instruction, il),
                         operand_to_il(instruction, il, first=False),
                         flags='zs')
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "AND":
        tmp = il.and_expr(instruction.get_size(),
                          operand_to_il(instruction, il),
                          operand_to_il(instruction, il, first=False),
                          flags='zs')
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "XOR":
        tmp = il.xor_expr(instruction.get_size(),
                          operand_to_il(instruction, il),
                          operand_to_il(instruction, il, first=False),
                          flags='zs')
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "SHL":
        tmp = il.shift_left(instruction.get_size(),
                            operand_to_il(instruction, il),
                            operand_to_il(instruction, il, first=False))
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "SHR":
        tmp = il.logical_shift_right(
            instruction.get_size(), operand_to_il(instruction, il),
            operand_to_il(instruction, il, first=False))
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "NOT":
        tmp = il.not_expr(instruction.get_size(),
                          operand_to_il(instruction, il))
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "NEG":
        tmp = il.neg_expr(instruction.get_size(),
                          operand_to_il(instruction, il),
                          flags="zsc")
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "INC":
        tmp = il.add(instruction.get_size(),
                     operand_to_il(instruction, il),
                     il.const(1, 1),
                     flags="zso")
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "DEC":
        tmp = il.sub(instruction.get_size(),
                     operand_to_il(instruction, il),
                     il.const(1, 1),
                     flags="zso")
        il.append(store_result(instruction, tmp, il))
    elif instruction.opcode == "CMP":
        # built in handling for sub for zero and carry flag
        il.append(
            il.sub(instruction.get_size(),
                   operand_to_il(instruction, il),
                   operand_to_il(instruction, il, first=False),
                   flags='zc'))
    elif instruction.opcode == "MOV":
        il.append(
            store_result(instruction,
                         operand_to_il(instruction, il, first=False), il))
    elif instruction.opcode == "LEA":
        il.append(store_result(instruction, il.reg(8, instruction.src_reg),
                               il))
    elif instruction.opcode == "NOP":
        il.append(il.nop())
    else:
        il.append(il.unimplemented())