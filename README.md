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

Build the relation graph of the kernel symbols:
```
# objdump -d vmlinux > kernel_disassembly.txt
# ./symrel.py -b kernel_disassembly.txt 
Done.
```

Get all callees of `down_read`

```
# echo down_read | ./symrel.py get callees 
__fentry__
call_rwsem_down_read_failed
```

Get all callees of `down_read` recursively with max depth = 2 (recur 2), with tracing (-t)
(In case this could gets long as recur depth increases, redirect the output to a file and read it with vim with `:set nowrap` for better readability)

```
# echo down_read | ./symrel.py -t get recur 2 callees 


              call at +14                                  call at +15                          
[down_read] ┬────────────> [call_rwsem_down_read_failed] ─────────────> [rwsem_down_read_failed]
            │
            │ call at +0              
            └───────────> [__fentry__]
```

Get all callers of `down_read` which does not call or jump to `up_read`:

```
# echo down_read | ./symrel.py get callers,jumpers which not call to up_read and not jump to up_read
c_start
m_start
request_trusted_key
s_start
sysvipc_proc_start
trace_event_read_lock
```

## Demo: finding the readers who own a rwsem in vmcore

rwsem does not store information for reader-owners (at least not all of them). To find a reader-pwner from vmcore can be tricky. Normally the first approach would be to search all processes' stack frames to detect who may be referring to the rwsem. This is based on an assumption that a rwsem owner holds the rwsem address in its stack frame, which, again, may not be true.

In this example we provide another approach using this tool.

We have a stalled environment due to heavy lock contention. The rwsem under contention is hold by a reader. Load is > 10000 and we want to find who the current reader-owners are.
First, get all unique functions from all backtraces and save to a file named "all_funcs.txt". These are the kernel functions the vmcore's stack frames recorded:
```
crash> foreach bt | grep "#[0-9]" | awk '{print $3}' | sort | uniq > all_funcs.txt

```

Second, list all symbols from the SymbolRelation graph. The output is already sorted. Some symbols from the vmcore may not exist in the vmlinux image (separate kernel modules, etc), which we used to build the graph:

```
# ./symrel.py FROM ALL GET SELF > symrel_funcs.txt
# wc -l symrel_funcs.txt
30731 symrel_funcs.txt
```

Define a new `stackjump` relation to relate symbols to what it can recursively jump to. These are functions that may "share" the same stack frame with the starting symbol (very roughly):

```
# ./symrel.py -d stackjump GET RECUR -1 jumpees
```

Next, we define a new `stackcall` relation based on `stackjump`. This relates a symbol to what the next symbol can be in its next stack frame:

```
# ./symrel.py -d stackcall GET SELF,stackjumpees GET callees GET SELF,stackjumpees
```

These are the functions from vmcore which `stackcall` to `up_read`. 

```
# comm -12 all_funcs.txt symrel_funcs.txt | ./symrel.py WHICH stackcall to up_read
__access_remote_vm
__do_page_fault
proc_pid_cmdline_read
task_numa_work
```
The next step will be to find the processes with these 4 functions in their backtrace, and not in the rwsem's wait_list, hopefully that will contain the reader-owners of the rwsem.

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
