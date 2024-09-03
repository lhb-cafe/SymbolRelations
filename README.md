This script builds call/jump relations between symbols from assembly. An assembly file can be generated from objdump. Once we built the relation graph, we can use the following command to reference them:
```
# ./symrel.py -h
Usage:
./symrel.py -b,--build: <objdump_file>
    Build the relation data. Need to be run first.

./symrel.py [FROM <input>] <command> [<command> [...]]
Available <input> options (default 'PIPE'):
    ALL: all available symbols from relation data (built by -b)
    FILE <file_path>: comma separated list of symbols from file
    PIPE: load symbols from stdin or '-p'
Available <command> options:
    GET SELF|<relation><ees|ers>
    WHICH <relation> <to|from> <symbol>
Available relations: ['call', 'jump']

boolean operations AND/OR/NOT are supported.
```

## Examples
Build the relation graph of the Linux Kernel symbols:
```
# objdump -d vmlinux > kernel_disassembly.txt
# ./symrel.py -b kernel_disassembly.txt 
Done.
```

Count functions in the Linux kernel calling `down_read`:  
```
# echo down_read | ./symrel.py FROM PIPE GET callers | wc -l
140
```

`PIPE` is the default input, so the `FROM PIPE` clause can be omitted:
```
# echo down_read | ./symrel.py GET callers | wc -l
140
```

Note that it is also equivalent to listing all available symbols which calls `down_read`:
```
# ./symrel.py FROM ALL WHICH call to down_read | wc -l
140
```

Check if all these `down_read` callers also calls  `up_read`:
```
# echo down_read | ./symrel.py GET callers WHICH call to up_read | wc -l
122
```

Who calls `down_read` without calling `up_read`? Pick one to investigate:
```
# echo down_read | ./symrel.py GET callers WHICH NOT call to up_read | head -1
__pci_disable_link_state
```

Turns out instead of calling, `__pci_disable_link_state` jumps to up_read
```
# echo __pci_disable_link_state | ./symrel.py GET jumpees
dev_warn
up_read
```

## Grammar
Except for the special options `-b` and `-h`, the top level of the script parameter is a `<statement>`, which can be expressed by a context free grammar.
```
./symrel.py <statement>
```
where `<statement>` (S0) supports boolean operations:
```
S0 -> S1 | NOT S1 | S0 AND S2 | S0 OR S2
S2 -> S0
```
and in its simplest form (S1) consists of an input clause (F0) and an operation clause (O0):
```
S1 -> F0 O0
```
The input clause (F0) is either empty, in which case, the default `FROM PIPE` option is used, or `FROM <input>`
```
F0 -> ^ | FROM I0
I0 -> FILE <syntax_for_file_path> | PIPE | ALL
```
The operation clause (O0) consists of two operations GET (G0) and WHICH (W0), both of which support boolean operations:
```
O0 -> GET G0 | WHICH W0
G0 -> G1 | NOT G1 | G0 AND G2 | G0 OR G2
W0 -> W1 | NOT W1 | W0 AND W2 | W0 OR W2
G2 -> G0
W2 -> W0
```
and in their simplest forms (G1, W1):
```
G1 -> R0SUF0
W1 -> R0 SUF1
R0 -> call | jump
SUF0 -> ees | ers
SUF1 -> to | from
```

The CFG of `<statement>`:
```
Non-terminals:
	S0, S1, S2, F0, O0, I0, G0, G1, G2, W0, W1, W2, R0, SUF0, SUF1
Start Symbol:
	S0
Production Rules:
	S0 -> S1 | NOT S1 | S0 AND S2 | S0 OR S2
	S2 -> S0
	S1 -> F0 O0
	F0 -> ^ | FROM I0
	I0 -> FILE <syntax_for_file_path> | PIPE | ALL
	O0 -> GET G0 | WHICH W0
	G0 -> G1 | NOT G1 | G0 AND G2 | G0 OR G2
	W0 -> W1 | NOT W1 | W0 AND W2 | W0 OR W2
	G1 -> R0SUF0
	W1 -> R0 SUF1
	G2 -> G0
	W2 -> W0
	R0 -> call | jump
	SUF0 -> ees | ers
	SUF1 -> to | from
```

The script is only expected to work with this exact syntax. Using it with a different syntax might not throw any error, but the behavior is undefined nevertheless.
