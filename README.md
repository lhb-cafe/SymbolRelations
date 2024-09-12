This script builds call/jump relations between symbols from assembly. An assembly file can be generated from objdump. Once we built the relation graph, we can use the following command to reference them:
```
# ./symrel.py -h
Usage:
-b,--build: <objdump_file>
    Build the relation data. Need to be run first.

-t,--trace [BACKWARD]
    Print traces from starting symbols to result symbols
    Must be placed as the first options

./symrel.py [-t|--trace [BACKWARD]] [FROM <input>] <command> [<command> [...]]

Available <input> options (default 'PIPE'):
    ALL: all available symbols from relation data (built by -b)
    PIPE: load symbols from stdin or '-p'
Available <command> options:
    GET [RECUR n] <SELF|{relation}ers/ees>[,[RECUR n] <...>[...]]
    WHICH [NOT] [RECUR n] <{relation} to|from {symbol}> [<OR|AND> [NOT] [RECUR n] <...> [...]]
Available relations: ['call', 'jump']
```

## Examples
Build the relation graph of the Linux Kernel symbols:
```
# objdump -d vmlinux > kernel_disassembly.txt
# ./symrel.py -b kernel_disassembly.txt 
Done.
```

Count functions in the Linux kernel calling `down_read` (since a 'FROM' clause is not specified, the default 'FROM PIPE' will be used):  
```
# echo down_read | ./symrel.py GET callers | wc -l
140
```

Note that it is also equivalent to listing all available symbols which calls `down_read`, except 'FROM ALL' would be slower because it has to filter out a lot of irrelevant symbols from the starting set (FROM ALL):
```
# ./symrel.py FROM ALL WHICH call to down_read | wc -l
140
```

What functions calls `down_read` without calling or jumping to `up_read`?
```
# echo down_read | ./symrel.py GET callers WHICH not call to up_read and not jump to up_read > funcs.txt
# cat funcs.txt
c_start
m_start
request_trusted_key
s_start
sysvipc_proc_start
```

Do their callers or jumpers ever call to up_read?
```
# cat funcs.txt | ./symrel.py GET self,jumpers,callers WHICH call to up_read or jump to up_read
request_master_key.isra.5
```
We can use the `-t` option to trace it back to the starting symbol `request_trusted_key`. We can also confirm that `request_master_key.isra.5` is the only caller to `request_trusted_key`:

```
# cat funcs.txt | ./symrel.py -t get self,jumpers,callers which call to up_read or jump to up_read

                        call                                call           
[request_trusted_key] ─<───── [request_master_key.isra.5] ──────> [up_read]

# echo request_trusted_key | ./symrel.py -t GET callers or jumpers

                        call                             
[request_trusted_key] ─<───── [request_master_key.isra.5]
```

What about the other 4 symbols `c_start`, `m_start`, `s_start`,  and `sysvipc_proc_start`? It turns out these symbols are stored as function pointers which we may not be able to get from the objdump the clear call relations. But we can at least confirm the `stop` version of these symbols do call `up_read`:

```
# echo c_stop, m_stop, s_stop, sysvipc_proc_stop | ./symrel.py -t WHICH call to up_read or jump to up_read

           jmp           
[c_stop] ─────> [up_read]

           jmp           
[m_stop] ─────> [up_read]

           call           
[s_stop] ──────> [up_read]

                      jmp           
[sysvipc_proc_stop] ─────> [up_read]
```


## Grammar
Except for the special options `-b` and `-h`, the top level of the script parameter is a `<statement>`, which can be expressed by a context free grammar.
```
./symrel.py <statement>
```
where `<statement>` (S0) supports boolean operations:
```
S0 -> S1 | -t S1 | -t BACKWARD S1 | NOT S1 | S0 AND S2 | S0 OR S2
S2 -> S0
```
and in its simplest form (S1) consists of an input clause (F0) and an operation clause (O0):
```
S1 -> F0 O0
```
The input clause (F0) is either empty, in which case, the default `FROM PIPE` option is used, or `FROM <input>`
```
F0 -> ^ | FROM I0
I0 -> PIPE | ALL
```
The operation clause (O0) consists of two operations GET (G0) and WHICH (W0), both of which support boolean operations:
```
O0 -> GET G0 | WHICH W0
G0 -> G1 | NOT G0 | G0 AND G2 | G0 OR G2
W0 -> W1 | NOT W0 | W0 AND W2 | W0 OR W2
G2 -> G0
W2 -> W0
```
and in their simplest forms (G1, W1):
```
G1 -> R0SUF0 | RECUR n R0SUF0
W1 -> R0 SUF1 | RECUR n R0 SUF1
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
	S0 -> S1 | -t S1 | -t BACKWARD S1 | NOT S1 | S0 AND S2 | S0 OR S2
	S2 -> S0
	S1 -> F0 O0
	F0 -> ^ | FROM I0
	I0 -> PIPE | ALL
	O0 -> GET G0 | WHICH W0
	G0 -> G1 | NOT G0 | G0 AND G2 | G0 OR G2
	W0 -> W1 | NOT W0 | W0 AND W2 | W0 OR W2
	G1 -> R0SUF0 | RECUR n R0SUF0
	W1 -> R0 SUF1 | RECUR n R0 SUF1
	G2 -> G0
	W2 -> W0
	R0 -> call | jump
	SUF0 -> ees | ers
	SUF1 -> to | from
```

The script is only expected to work with this exact grammar. Using it with a non matching language may result in errors or undefined behaviors
