import re

relations_re = {
    'call': re.compile(r'^([0-9a-fx]+):\s*e8[0-9a-f\s]+(call)q?\s+[0-9a-fx]+\s*<(.+?)>'),
    'jump': re.compile(r'^([0-9a-fx]+):\s*[0-9a-f\s]+(jmp|ja|jae|jb|jbe|jl|jle|jg|jge|jc|jnc|jo|jno|js|jns|jz|jnz)q?\s+[0-9a-fx]+\s*<([^+>]*)>')
}

relations = list(relations_re.keys())

def parse(sr, objdump_file):
    func_pattern = re.compile(r'^([0-9a-f]+) <(.+?)>:')
    with open(objdump_file, 'r') as objdump:
        for line in objdump:
            match = func_pattern.match(line)
            if match:
                src_addr = match.groups()[0]
                src_sym = match.groups()[1]
                continue
            relation = None
            for rel, pattern in relations_re.items():
                match = pattern.match(line)
                if match:
                    relation = rel
                    break
            if not relation:
                continue
            # a match of relation is found
            match_addr = match.groups()[0]
            instruction = match.groups()[1]
            dst_sym = match.groups()[2]
            if src_sym:
                sr.register_relation(src_sym, dst_sym, relation, instruction, int(match_addr, 16) - int(src_addr, 16))
            else:
                print("Error matching relation", relation, "[None] ->", dst_sym, "without a matching caller", file=sys.stderr);
                return 1
    return 0