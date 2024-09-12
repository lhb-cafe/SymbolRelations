#!/usr/bin/python3

import sys
from symrellib import SymbolRelations, available_relations

def help(name):
    print("Usage:")
    print(name, "-b,--build: <objdump_file>")
    print("    Build the relation data. Need to be run first.\n")
    print(name, "[FROM <input>] <command> [<command> [...]]")
    print("Available <input> options (default 'PIPE'):")
    print("    ALL: all available symbols from relation data (built by -b)")
    print("    FILE <file_path>: comma separated list of symbols from file")
    print("    PIPE: load symbols from stdin or '-p'")
    print("Available <command> options:")
    print("    GET SELF|<relation><ees|ers>")
    print("    WHICH <relation> <to|from> <symbol>")
    print("Available relations:", list(available_relations.keys()))
    print("\nBoolean operations AND/OR/NOT are supported. See examples below.")
    print("For a strict definition of the syntax, please refer to the repo README.")
    print("\nExamples:")
    print("Print all symbols from the relation data:")
    print("    symrel.py FROM ALL GET SELF")
    print("Get all callers of symX which also call symY:")
    print("    echo symX | symrel.py GET callers WHICH call to symY")
    print("\nExamples with boolean operations:")
    print("Get all callers of symX which do not call symY:")
    print("    symrel.py FROM ALL WHICH call to symX AND NOT call to symY")
    print("Add to a list of symbols in sym.txt with their jumpers:")
    print("    symrel.py FROM FILE sym.txt GET SELF OR jumpers > sym.txt")

def push_bool_ops(argv, cur, bool_ops):
    binary = False
    if argv[cur] in ('AND', 'OR'):
        bool_ops.append(argv[cur]); cur += 1
        binary = True
    if argv[cur] == 'NOT':
        bool_ops.append(argv[cur]); cur += 1
    return cur, binary

def pop_bool_ops(argv, cur, bool_ops):
    while len(bool_ops) > 0:
         ops = bool_ops.pop()
         argv.insert(cur, ops)

def consume_bool_ops(input, cache, universe, bool_ops):
    while len(bool_ops) > 0:
        ops = bool_ops.pop()
        if ops == 'AND':
            cache &= input
        elif ops == 'OR':
            cache |= input
        else:
            if universe == None:
                # only build all_cache when absolutely needed
                universe = get_all_cache()
            input = universe - input
    if cache == None:
        cache = input
    return cache

def handle_one_command(argv, cur, in_cache):
    cache = None
    bool_ops = list()
    error = None
    ret = None
    target_sym = None
    recur = 1
    opt = argv[cur]; cur += 1
    while cur < len(argv):
        cur, binary = push_bool_ops(argv, cur, bool_ops)
        if cache != None and not binary: # end of current command
            pop_bool_ops(argv, cur, bool_ops)
            break
        if argv[cur] == 'RECUR':
            recur = int(argv[cur+1]); cur +=2
        relation = None
        if opt == 'GET': # handle GET commands
            universe = None
            if argv[cur] == 'SELF':
                ret = in_cache; cur += 1
                cache = consume_bool_ops(ret, cache, universe, bool_ops)
                continue
            else:
                for rel in available_relations.keys():
                    if argv[cur].startswith(rel):
                        relation = rel
                        break
                if relation == None: # end of current command
                    pop_bool_ops(argv, cur, bool_ops)
                    break
                if argv[cur].endswith(('ees', 'ers')):
                    forward = argv[cur].endswith('ees'); cur += 1
                else:
                    error = "GET with invalid argument: " + argv[cur]
                    break
        else: # handle WHICH commands
            universe = in_cache
            if argv[cur] in available_relations.keys():
                relation = argv[cur]; cur += 1
            else: # end of current command
                pop_bool_ops(argv, cur, bool_ops)
                break
            if argv[cur] in ('to', 'from'):
                forward = (argv[cur] == 'to'); cur += 1
            else:
                error = "WHICH with invalid argument: " + argv[cur]
                break
            if cur >= len(argv):
                error = "WHICH without symbol"
                break
            target_sym = argv[cur]; cur += 1
        ret = sr.search(in_cache, relation, forward, target_sym, recur)
        cache = consume_bool_ops(ret, cache, universe, bool_ops)
        continue
    return cache, cur, error

def handle_statement(argv, cur, in_cache, out_cache):
    cache = None
    bool_ops = list()
    error = None
    has_from = False
    ret = None
    while not error and cur < len(argv):
        cur, binary = push_bool_ops(argv, cur, bool_ops)
        if cache != None and not binary: # end of current statement
            pop_bool_ops(argv, cur, bool_ops)
            break
        if argv[cur] == 'FROM':
            in_cache = None
            has_from = True
            if argv[cur + 1] == 'ALL':
                in_cache = sr.build_cache(set(sr.dict.keys()))
            else:
                if argv[cur + 1] == 'FILE':
                    in_buf = open([cur + 2], 'r'); cur += 1
                elif argv[cur + 1] == 'PIPE':
                    if out_cache:
                        in_cache = out_cache
                        out_cache = None
                    else:
                        in_buf = sys.stdin
                else:
                    in_buf = argv[cur + 1]
                if not in_cache:
                    in_set = set()
                    for line in in_buf:
                        in_set.update(set(line.strip('\n\r').split(", ")))
                    in_cache = sr.build_cache(in_set)
            cur += 2
        if in_cache == None:
            if not has_from:
                # default is FROM PIPE
                argv.insert(cur, 'PIPE')
                argv.insert(cur, 'FROM')
                continue
            else:
                error = "bad FROM clause"
                break
        if argv[cur] in ('WHICH', 'GET'):
            ret, cur, error = handle_one_command(argv, cur, in_cache)
        else:
            error = "unknown command: " + argv[cur]
        if not error:
            cache = consume_bool_ops(ret, cache, None, bool_ops)
        continue
    return cache, cur, error

def get_all_cache():
    global all_cache
    if all_cache == None:
        all_cache = sr.build_cache(set(sr.dict.keys()))
    return all_cache

all_cache = None
backward_tracing = False
sr_file = '__sr_data.pkl'
if __name__ == "__main__":
    sr = SymbolRelations()
    cur = 1
    error = None
    argv = list(sys.argv)
    if len(argv) < 2:
        argv.append('-h')

    # handle 'build' and 'help'
    if argv[cur] in ('-b','--build'):
        sr.build(argv[cur+1])
        sr.save(sr_file)
        print("Done."); exit(0)
    elif argv[cur] in ('-h','--help'):
        help(argv[0]); exit(0)

    sr.load(sr_file)
    if argv[cur] in ('-t','--trace'):
        sr.set_tracing(True); cur += 1
        if argv[cur] == 'BACKWARD':
            backward_tracing = True; cur += 1

    in_cache = None
    out_cache = None
    while not error and cur < len(argv):
        out_cache, cur, error = handle_statement(argv, cur, in_cache, out_cache)
    if error:
        print("argument", cur, "error:", error, file=sys.stderr)
        help(argv[0]); exit(1)
    elif out_cache:
        out_cache.print(backward = backward_tracing)
