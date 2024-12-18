from elftools.elf.elffile import ELFFile
from capstone import Cs, x86, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct
import copy
import time

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


class to_capstone_opr:
    def __init__(self, reg = None, imm = None):
        if reg != None:
            self.type = x86.X86_OP_REG
            self.reg = reg
        else: # imm != None
            self.type = x86.X86_OP_IMM
            self.imm = imm


class x86_operand:
    def __init__(self, inst, operand = None):
        # operand != None
        self.type = operand.type
        if self.type == x86.X86_OP_IMM:
            self.imm = operand.imm
        elif self.type == x86.X86_OP_REG:
            # resolve while we can
            if operand.reg == x86.X86_REG_RIP:
                self.type = x86.X86_OP_IMM
                self.imm = inst.address + inst.size
            # used for X86_OP_MEM when base/index is not specified
            elif operand.reg == x86.X86_REG_INVALID:
                self.type = x86.X86_OP_IMM
                self.imm = 0
            else:
                self.type = x86.X86_OP_REG
                self.reg = operand.reg
        elif self.type == x86.X86_OP_MEM:
            self.base = x86_operand(inst = inst, operand = to_capstone_opr(reg = operand.mem.base))
            self.index = x86_operand(inst = inst, operand = to_capstone_opr(reg = operand.mem.index))
            # resolve while we can
            if self.base.type == x86.X86_OP_IMM and self.index.type == x86.X86_OP_IMM:
                va = self.index.imm * operand.mem.scale + self.base.imm + operand.mem.disp
                res = get_int_from_va(va)
                if res != None:
                    self.type = x86.X86_OP_IMM
                    self.imm = res
            if self.type == x86.X86_OP_MEM:
                self.scale = operand.mem.scale
                self.disp = operand.mem.disp
                self.normalize()
        self.rehash()

    def __repr__(self):
        if self.type == x86.X86_OP_IMM:
            return f'{self.imm}'
        elif self.type == x86.X86_OP_REG:
            return f'{md.reg_name(self.reg)}'
        elif self.type == x86.X86_OP_MEM:
            return f'({self.base.__repr__()} + {self.scale} * {self.index.__repr__()} + {hex(self.disp)})'

    def normalize(self):
        if self.type != x86.X86_OP_MEM:
            return
        if self.base != None and self.base.type == x86.X86_OP_IMM:
            self.disp += self.base.imm
            self.base = None
        if self.index != None and self.index.type == x86.X86_OP_IMM:
            self.disp += (self.index.imm * self.scale)
            self.index = None
            self.scale = 0
        # index is equivalent to base if scale is 1
        if self.scale == 1:
            # move index to base if we can
            if self.base == None:
                self.base = self.index
                self.index = None
                self.scale = 0
            # otherwise, sort
            elif self.base.reg < self.index.reg:
                    tmp = self.base
                    self.base = self.index
                    self.index = tmp
        self.rehash()

    def rehash(self):
        if self.type == x86.X86_OP_IMM:
            self.hash = (self.imm.__hash__() << 2)
        elif self.type == x86.X86_OP_REG:
            self.hash = (self.reg.__hash__() << 2) + 1
        elif self.type == x86.X86_OP_MEM:
            self.hash = ((self.base, self.index, self.scale, self.disp).__hash__() << 2) + 2
        else:
            raise ValueError("invalid operand")

    # ignore the context when comparing
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        elif self.type == x86.X86_OP_IMM:
            return other.type == x86.X86_OP_IMM and other.imm == self.imm
        elif self.type == x86.X86_OP_REG:
            return other.type == x86.X86_OP_REG and other.reg == self.reg
        elif self.type == x86.X86_OP_MEM and other.type == x86.X86_OP_MEM:
            return (self.base, self.index, self.scale, self.disp) == (other.base, other.index, other.scale, other.disp)
        return False

    def __hash__(self):
        return self.hash

    def next_ip(self):
        return self.inst.address + self.inst.size


class x86_resolver:
    def __init__(self):
        self.src_to_dst = {}
        self.dst_to_src = {}
        self.res = {}
        self.margin = {}
        self.targets = None

    def map_opr(self, dst_opr = None, src_opr = None):
        if src_opr in self.dst_to_src.get(dst_opr, set()):
            return
        dict_set_add(self.src_to_dst, src_opr, dst_opr)
        dict_set_add(self.dst_to_src, dst_opr, src_opr)
        if src_opr.type == x86.X86_OP_IMM:
            dict_set_add(self.margin, dst_opr, src_opr.imm)
        if dst_opr.type == x86.X86_OP_MEM:
            self.add_mem_opr(dst_opr)
        if src_opr.type == x86.X86_OP_MEM:
            self.add_mem_opr(src_opr)

    def add_mem_opr(self, mem_opr):
        if mem_opr.base != None:
            self.map_opr(dst_opr = mem_opr, src_opr = mem_opr.base)
        if mem_opr.index != None:
            self.map_opr(dst_opr = mem_opr, src_opr = mem_opr.index)

    def set_targets(self, targets, recur):
        self.targets = set()
        self.__set_targets(targets, recur)

    def __set_targets(self, targets, recur):
        self.targets |= targets
        if recur == 0:
            return
        for tgt in targets:
            self.set_targets(targets = self.dst_to_src.get(tgt, set()), recur = recur - 1)

    def get_res(self, opr, margin_only = False, margin = True):
        res = self.res.get(opr, set())
        margin_res = self.margin.get(opr, set())
        if margin_only:
            return margin_res - res
        if margin:
            return margin_res | res
        return res - margin_res

    def resolve(self):
        # get pending operands which may be updated by margin
        pendings = set()
        for m in self.margin.keys():
            pendings |= self.src_to_dst.get(m, set())
            # if m is memorey operand and either base or index is None, there is a chance
            # that another memory operand using the same registers can be resolved based on it
            if m.type == x86.X86_OP_MEM and (m.base == None or m.index == None):
                for p in (self.src_to_dst.get(m.base, set()) | self.src_to_dst.get(m.index, set())):
                    if p.type == x86.X86_OP_MEM:
                        pendings.add(p)
        if self.targets != None: # trim to avoid unneeded work
            pendings &= self.targets

        # get new margin from pending
        new_margin = {}
        for opr in pendings:
            new_margin[opr] = set()
            for src_opr in (self.dst_to_src[opr] & set(self.margin.keys())):
                new_margin[opr] |= self.margin[src_opr]
            if opr.type == x86.X86_OP_IMM or opr.type == x86.X86_OP_REG:
                assert len(new_margin[opr]) > 0
                continue
            # opr.type == x86.X86_OP_MEM
            for b in self.get_res(opr.base, margin_only = True):
                # indirect resolutions from another resolved memory operand
                tmp_opr = copy.copy(opr)
                tmp_opr.base = to_capstone_opr(imm = b)
                tmp_opr.normalize()
                new_margin[opr] |= (self.res.get(tmp_opr, set()) | self.margin.get(tmp_opr, set()))
                # direct resolutions
                if opr.scale == 0:
                    res = get_int_from_va(b + opr.disp)
                    if res != None:
                        new_margin[opr].add(res)
                else:
                    for idx in self.get_res(opr.index):
                        res = get_int_from_va(b + opr.scale * idx + opr.disp)
                        if res != None:
                            new_margin[opr].add(res)
            for idx in self.get_res(opr.index, margin_only = True):
                # indirect resolutions from another resolved memory operand
                tmp_opr = copy.copy(opr)
                tmp_opr.index = to_capstone_opr(imm = idx)
                tmp_opr.normalize()
                new_margin[opr] |= (self.res.get(tmp_opr, set()) | self.margin.get(tmp_opr, set()))
                # direct resolutions
                for b in self.get_res(opr.base, margin = False):
                    res = get_int_from_va(b + opr.scale * idx + opr.disp)
                    if res != None:
                        new_margin[opr].add(res)
            if len(new_margin[opr]) == 0:
                del new_margin[opr]

        # merge old margin into res
        for opr, res in self.margin.items():
            if opr in self.res.keys():
                self.res[opr] |= res
            else:
                self.res[opr] = res

        # set margin to new_margin
        self.margin = new_margin


# helper function: the value of the dictionary must be sets
def dict_set_add(d, key, val):
    if key in d.keys():
        d[key].add(val)
    else:
        d[key] = {val}

cache_va = {}
def get_int_from_va(va):
    size = addr_bytes # FIXME: use actual size from instruction
    if va in cache_va.keys():
        return cache_va[va]
    for s in mapped_sections:
        if s.header.sh_addr <= va < s.header.sh_addr+s.header.sh_size-size:
            byte_array = s.data()[va-s.header.sh_addr : va-s.header.sh_addr+size]
            ret = struct.unpack('Q', byte_array)[0]
            if verbose:
                print(f'va at {hex(va)} is {byte_array}', ret in addr_to_symbol.keys(), s.name)
            cache_va[va] = ret
            return ret
    cache_va[va] = None
    return None


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


def register_indirect_insts(sr, symbol, idrt_target_dict, resolver):
    recur = 5
    found_cutoff = 5 # number of symbols found before we return
    pending = {}
    if verbose:
        print('============= dst_to_src start ===============')
        for k, v in resolver.dst_to_src.items():
            print(k, v)
        print('============= dst_to_src end ===============')
    for tgt in idrt_target_dict.keys():
        pending[tgt] = 0
    resolver.set_targets(set(idrt_target_dict.keys()), recur)
    while len(pending.keys()) > 0 and recur > 0:
        for tgt in list(pending.keys()):
            for res in resolver.get_res(tgt, margin_only = True):
                if verbose:
                    print(md.reg_name(tgt.reg), '--->', res, recur)
                    #rbx = to_capstone_opr(reg = x86.X86_REG_RBX)
                    #print('rbx', resolver.get_res(to_capstone_opr(reg = x86.X86_REG_RBX), recur))
                if not res in addr_to_symbol.keys():
                    continue
                for dst_sym in addr_to_symbol[res]:
                    for inst_tupl in idrt_target_dict[tgt]:
                        sr.register_relation(symbol.name, dst_sym, inst_tupl[0], f'idrt_{inst_tupl[0]}_{recur}', inst_tupl[1])
                pending[tgt] += 1 # count only once if multiple dst_sym share the same va
            if pending[tgt] >= found_cutoff:
                del pending[tgt]
                continue
        resolver.resolve()
        recur -= 1


def parse_inst(sr, inst, symbol, idrt_target_dict, resolver):
    if inst.mnemonic.startswith('mov'): 
        dst_opr = x86_operand(inst = inst, operand = inst.operands[0])
        src_opr = x86_operand(inst = inst, operand = inst.operands[1])
        resolver.map_opr(dst_opr, src_opr)
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
        idrt_target = x86_operand(inst = inst, operand = inst.operands[0])

    # if we can translate indirect target into direct target, do it now
    # e.g., "call qword ptr [0xffffffff82040ba8]"
    if idrt_target != None and idrt_target.type == x86.X86_OP_IMM:
        if idrt_target.imm in addr_to_symbol.keys():
            drt_targets = addr_to_symbol[idrt_target.imm]
        idrt_target = None

    # found a direct target
    if drt_targets != None:
        for tgt in drt_targets:
            # special case for the linux thunk calls, which are actually indirect calls
            if is_linux and tgt.startswith(linux_thunk_prefix):
                # get the suffix of the thunk call symbol, e.g., "rax" for "__x86_indirect_thunk_rax"
                idrt_reg_str = tgt[len(linux_thunk_prefix):]
                idrt_reg = getattr(x86, f'X86_REG_{idrt_reg_str.upper()}')
                idrt_target = x86_operand(inst, to_capstone_opr(reg = idrt_reg))
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
    global verbose
    verbose = False
    sym_addr = symbol['st_value']
    processed = 0
    offset = symbol['st_value'] - text_section['sh_addr']
    code_section = text_section.data()[offset : offset + size + max_inst_size - 1]
    idrt_target_dict = {}
    resolver = x86_resolver()
    for inst in md.disasm(code_section, symbol['st_value']):
        parse_inst(sr, inst, symbol, idrt_target_dict, resolver)
        processed += inst.size
        if processed >= size:
            break

    if len(idrt_target_dict) > 0:
        register_indirect_insts(sr, symbol, idrt_target_dict, resolver)
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
        start_time = time.time()

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
        print(f"\rELF done, seconds spent: {time.time() - start_time}")
    return 0
