from elftools.elf.elffile import ELFFile
from capstone import Cs, x86, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

relations = ['call', 'jump']

elf = None

max_inst_size = 15 # x86 spec
md = None
addr_bytes = None
addr_to_symbol = dict()
is_linux = False
linux_version = None


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


def parse_inst(sr, inst, symbol):
    if inst.mnemonic.startswith('j'):
        rel = 'jump';
    elif inst.mnemonic.startswith('call'):
        rel = 'call'
    else:
        return

    offset = inst.address - symbol['st_value']
    o = inst.operands[0]

    # e.g.,  "call 0xffffffff8175d000"
    if o.type == x86.X86_OP_IMM:
        va = int(inst.op_str, 16) # TODO: maybe we should calculate from inst.operands[0].imm for performance
        if va in addr_to_symbol.keys():
            drt_targets = addr_to_symbol[va] # one addr can correspond to multiple symbols
            for tgt in drt_targets:
                sr.register_relation(symbol.name, tgt, rel, inst.mnemonic, offset)


def parse_sym(sr, symbol, size, text_section, md):
    sym_addr = symbol['st_value']
    processed = 0
    offset = symbol['st_value'] - text_section['sh_addr']
    code_section = text_section.data()[offset : offset + size + max_inst_size - 1]
    for inst in md.disasm(code_section, symbol['st_value']):
        parse_inst(sr, inst, symbol)
        processed += inst.size
        if processed >= size:
            break
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
