from elftools.elf.elffile import ELFFile
from capstone import Cs, x86, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

relations = ['call', 'jump']

elf = None

max_inst_size = 15 # x86 spec
md = None
addr_bytes = None
addr_to_symbol = dict()
mapped_sections = []
is_linux = False
linux_version = None
linux_thunk_prefix = '__x86_indirect_thunk_'


class x86_contextual_operand:
    def __init__(self, inst = None, operand = None, reg = None):
        self.inst = inst
        if reg != None:
            self.type = x86.X86_OP_REG
            self.reg = reg
            return
        # operand != None
        self.operand = operand
        self.type = operand.type
        if self.type == x86.X86_OP_REG:
            self.reg = operand.reg

    # ignore the context when comparing
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        elif self.type == x86.X86_OP_IMM:
            return other.type == x86.X86_OP_IMM and other.operand.imm == self.operand.imm
        elif self.type == x86.X86_OP_REG:
            return other.type == x86.X86_OP_REG and other.reg == self.reg
        elif self.type == x86.X86_OP_MEM and other.type == x86.X86_OP_MEM:
            return other.operand.mem.base == self.operand.mem.base and \
                other.operand.mem.index == self.operand.mem.index and \
                other.operand.mem.scale == self.operand.mem.scale and \
                other.operand.mem.disp == self.operand.mem.disp
        return False

    # possible collisions are tolerable because the dict.keys() will not be too large anyway
    def __hash__(self):
        if self.type == x86.X86_OP_IMM:
            return self.operand.imm.__hash__()
        elif self.type == x86.X86_OP_REG:
            return self.reg.__hash__()
        elif self.type == x86.X86_OP_MEM:
            return self.operand.mem.base.__hash__() + self.operand.mem.index.__hash__()
        return id(self).__hash__()

    # try to compute the value of this operand
    # @reg_graph: a dict mapping an operand to operands from which it is assigned
    #             e.g., "mov rax, qword ptr [rdx + 0x28]"
    def resolve(self, operand_graph = {}, recur = 0):
        res = dict()
        # self is an immediate, easy
        if self.type == x86.X86_OP_IMM:
            res[recur] = {self.operand.imm}
        # self is a register, easy for RIP, which points to the next instruction
        elif self.type == x86.X86_OP_REG and self.reg == x86.X86_REG_RIP:
                res[recur] = {self.inst.address + self.inst.size}
        # self is memory
        elif self.type == x86.X86_OP_MEM:
            mem = self.operand.mem
            # resolve base
            if mem.base != x86.X86_REG_INVALID:
                if recur == 0: # out of recursion
                    return res
                opr = x86_contextual_operand(inst = self.inst, reg = mem.base)
                base_values = opr.resolve(operand_graph, recur - 1)
                if len(base_values) == 0: # unresolved
                    return res
            else:
                base_values = {recur: {0}}

            # resolve index
            if mem.index != x86.X86_REG_INVALID:
                if recur == 0: # running out of recursion
                    return res
                opr = x86_contextual_operand(inst = self.inst, reg = mem.index)
                index_values = opr.resolve(operand_graph, recur - 1)
                if len(index_values) == 0: # unresolved
                    return res
            else:
                index_values = {recur: {0}}

            for base_recur in base_values.keys():
                for index_recur in index_values.keys():
                    depth = min(base_recur, index_recur) # smaller recur -> deeper in recursion
                    for b in base_values[base_recur]:
                        for i in index_values[index_recur]:
                            dict_set_add(res, depth, i * mem.scale + b + mem.disp)

        # recursion
        if recur == 0:
            return res
        for o, s in operand_graph.items():
            if self != o:
                continue
            for other in s:
                for depth, recur_res in other.resolve(operand_graph, recur - 1).items():
                    if depth in res.keys():
                        res[depth] |= recur_res
                    else:
                        res[depth] = recur_res
            break
        return res


# the value of the dictionary must be sets
def dict_set_add(d, key, val):
    if key in d.keys():
        d[key].add(val)
    else:
        d[key] = {val}


def check_linux():
    rodata = elf.get_section_by_name('.rodata')
    if rodata == None:
        return
    global is_linux
    global linux_version
    index = rodata.data().find(b"Linux version")
    if index != -1:
        is_linux = True
        linux_version = rodata.data()[index:].split(b' ')[2]

    while is_linux:
        user_input = input(f"ELF is detected as Linux kernel version {linux_version}. Confirm? (Y/n): ")
        if user_input in ['', 'y', 'Y', 'yes', 'Yes', 'YES']:
            break
        elif user_input in ['n', 'N', 'no', 'No', 'NO']:
            is_linux = False
    if is_linux:
        print("ELF will be parsed as a Linux kernel image")
    return


def get_sym_from_elf(va):
    for s in mapped_sections:
        if s.header.sh_addr <= va < s.header.sh_addr+s.header.sh_size-addr_bytes:
            inst_va_bytes = s.data()[va-s.header.sh_addr : va-s.header.sh_addr+addr_bytes]
            inst_va = struct.unpack('Q', inst_va_bytes)[0]
            if inst_va in addr_to_symbol.keys():
                return addr_to_symbol[inst_va]
    return None


def register_indirect_insts(sr, symbol, idrt_target_dict, operand_graph):
    found_cutoff = 5 # number of symbols found before we return
    for idrt_target, idrt_insts_tupls in idrt_target_dict.items():
        recur = 5
        found = 0
        checked_va = set()
        res = idrt_target.resolve(operand_graph = operand_graph, recur = recur)
        while recur >= 0:
            try:
                # start from low recursion depth
                s = res[recur]
            except KeyError:
                recur -= 1
                continue
            recur -= 1

            for va in s:
                if va not in checked_va:
                    checked_va.add(va)
                    dst_symbols = get_sym_from_elf(va)
                    if dst_symbols == None:
                        continue
                    for dst_sym in dst_symbols:
                        for inst_tupl in idrt_insts_tupls:
                            sr.register_relation(symbol.name, dst_sym, inst_tupl[0], f'idrt_{inst_tupl[0]}_{recur}', inst_tupl[1])
                    found += 1 # count only once if multiple dst_sym share the same va

            if found >= found_cutoff:
                break


def parse_inst(sr, inst, symbol, idrt_target_dict, operand_graph):
    if inst.mnemonic.startswith('mov'):
        dst_opr = x86_contextual_operand(inst = inst, operand = inst.operands[0])
        src_opr = x86_contextual_operand(inst = inst, operand = inst.operands[1])
        dict_set_add(operand_graph, dst_opr, src_opr)
        return
    elif inst.mnemonic.startswith('j'):
        rel = 'jump';
    elif inst.mnemonic.startswith('call'):
        rel = 'call'
    else:
        return

    offset = inst.address - symbol['st_value']
    drt_targets = None # direct call target, e.g., "call 0xffffffff8175d000"
    idrt_target = None # indirect call target, e.g., "call rax" or "call qword ptr [rip + rax*8 - 0x8e7503]"
    o = inst.operands[0]

    # e.g.,  "call 0xffffffff8175d000"
    if o.type == x86.X86_OP_IMM:
        va = int(inst.op_str, 16) # TODO: maybe we should calculate from inst.operands[0].imm for performance
        if va in addr_to_symbol.keys():
            drt_targets = addr_to_symbol[va] # one addr can correspond to multiple symbols
    # e.g., "call rax"
    else:
        idrt_target = x86_contextual_operand(inst = inst, operand = inst.operands[0])

    # if we can translate indirect target into direct target, do it now
    # e.g., "call qword ptr [0xffffffff82040ba8]"
    if idrt_target != None:
        res = idrt_target.resolve()
        if len(res) > 0:
            idrt_target = None
            va = next(iter(res[0])) # resolve() can only return one element without any recursion
            if va in addr_to_symbol.keys():
                drt_targets = addr_to_symbol[va]

    # found a direct target
    if drt_targets != None:
        for tgt in drt_targets:
            # special case for the linux thunk calls, which are actually indirect calls
            if is_linux and tgt.startswith(linux_thunk_prefix):
                # get the suffix of the thunk call symbol, e.g., "rax" for "__x86_indirect_thunk_rax"
                idrt_reg_str = tgt[len(linux_thunk_prefix):]
                idrt_reg = getattr(x86, f'X86_REG_{idrt_reg_str.upper()}')
                idrt_target = x86_contextual_operand(reg = idrt_reg)
            # normal cases
            else:
                sr.register_relation(symbol.name, tgt, rel, inst.mnemonic, offset)

    # no need to proceed further if source symbol is already a linux thunk calls
    if is_linux and symbol.name.startswith(linux_thunk_prefix):
        return

    # found an indirect relation
    if idrt_target != None:
        dict_set_add(idrt_target_dict, idrt_target, (rel, offset))


def parse_sym(sr, symbol, size, text_section, md):
    sym_addr = symbol['st_value']
    processed = 0
    offset = symbol['st_value'] - text_section['sh_addr']
    code_section = text_section.data()[offset : offset + size + max_inst_size - 1]
    idrt_target_dict = {}
    operand_graph = {}
    for inst in md.disasm(code_section, symbol['st_value']):
        parse_inst(sr, inst, symbol, idrt_target_dict, operand_graph)
        processed += inst.size
        if processed >= size:
            break

    if len(idrt_target_dict) > 0:
        register_indirect_insts(sr, symbol, idrt_target_dict, operand_graph)
    return processed


def parse(sr, elf_file):
    global md
    global addr_to_symbol
    global elf
    global mapped_sections
    global addr_bytes
    with open(elf_file, 'rb') as f:
        elf = ELFFile(f)
        arch = elf.header['e_machine']
        if arch == 'EM_X86_32':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            addr_bytes = 4
        elif arch == 'EM_X86_64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            addr_bytes = 8
        else:
            print(f"ELF file not for x86, detected code {elf.header['e_machine']}")
            return 1
        md.detail = True
        check_linux()

        print("Checking sections ...")
        for section in elf.iter_sections():
            if hasattr(section.header, 'sh_addr') and section.header.sh_addr is not None:
                mapped_sections.append(section)
        mapped_sections = sorted(mapped_sections, key = lambda section: section.header.sh_addr)

        text = elf.get_section_by_name('.text')
        if text is None:
            print("No '.text' section found in the ELF file.")
            return 1
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            print("No '.symtab' section found in the ELF file.")
            return

        print("Parsing .symtab ...")
        sym_in_text = []
        for symbol in symtab.iter_symbols():
            if text['sh_addr'] <= symbol['st_value'] < text['sh_addr'] + text['sh_size']:
                sym_in_text.append(symbol)
                dict_set_add(addr_to_symbol, symbol['st_value'], symbol.name)
        sym_in_text = sorted(sym_in_text, key = lambda sym: sym['st_value'])
        sym_cnt = len(sym_in_text)
        print(f'Found {sym_cnt} symbols in .text section.')

        # Parse .text
        progress = -1
        for i in range(0, sym_cnt):
            symbol = sym_in_text[i]
            size = symbol['st_size']
            if i < sym_cnt - 1:
                size = max(size, sym_in_text[i+1]['st_value'] - symbol['st_value'])
            processed = parse_sym(sr, symbol, size, text, md)
            if processed < size:
                print(f'\rWarning: symbol {symbol.name} size = {size}, processed = {processed}')
            new_progress = (i + 1) * 100 // sym_cnt
            if new_progress > progress:
                progress = new_progress
                print(f"\rParsing .text: {progress}%", end="", flush=True)
        print("\rELF done")
    return 0
