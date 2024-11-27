from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import re

relations_re = {
    'call': re.compile(r'(call)q?'),
    'jump': re.compile(r'(jmp|ja|jae|jb|jbe|jl|jle|jg|jge|jc|jnc|jo|jno|js|jns|jz|jnz)q?')
}
relations = list(relations_re.keys())

elf = None

max_inst_size = 15 # x86 spec
md = None
addr_pattern = None
addr_to_symbol = dict()
is_linux = False
linux_version = None

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
    for rel, pattern in relations_re.items():
        op_match = pattern.match(inst.mnemonic)
        if op_match:
            addr_match = addr_pattern.match(inst.op_str)
            if addr_match:
                dst_addr = int(addr_match.groups()[0], 16)
                if dst_addr in addr_to_symbol.keys():
                    dst_symbol = addr_to_symbol[dst_addr]
                    sr.register_relation(symbol.name, dst_symbol, rel, op_match.groups()[0], inst.address - symbol['st_value'])
                    #print(f"registered relation {symbol.name} {op_match.groups()[0]} {dst_symbol}")

def parse_sym(sr, symbol, size, text_section, md):
    sym_addr = symbol['st_value']
    #print(f'{sym_addr:08x} <{symbol.name}>:')
    processed = 0
    offset = symbol['st_value'] - text_section['sh_addr']
    code_section = text_section.data()[offset : offset + size + max_inst_size - 1]
    for inst in md.disasm(code_section, symbol['st_value']):
        parse_inst(sr, inst, symbol)
        #print(f"{inst.address:08x}:\t{inst.bytes.hex()} \t{inst.mnemonic}\t{inst.op_str}")
        processed += inst.size
        if processed >= size:
            break
    return processed

def parse(sr, elf_file):
    global md
    global addr_pattern
    global addr_to_symbol
    global elf
    with open(elf_file, 'rb') as f:
        elf = ELFFile(f)
        arch = elf.header['e_machine']
        if arch == 'EM_X86_32':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            addr_pattern = re.compile(r'0x([0-9a-f]{8})')
        elif arch == 'EM_X86_64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            addr_pattern = re.compile(r'0x([0-9a-f]{16})')
        else:
            print(f"ELF file not for x86, detected code {elf.header['e_machine']}")
            return 1
        check_linux()


        text = elf.get_section_by_name('.text')
        if text is None:
            print("No '.text' section found in the ELF file.")
            return 1
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            print("No '.text' section found in the ELF file.")
            return 1

        print("Parsing .symtab ...")
        sym_in_text = []
        for symbol in symtab.iter_symbols():
            if text['sh_addr'] <= symbol['st_value'] < text['sh_addr'] + text['sh_size']:
                sym_in_text.append(symbol)
                addr_to_symbol[symbol['st_value']] = symbol.name
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
