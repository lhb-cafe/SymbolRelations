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

Examples:
Print all symbols from the relation data:
    symrel.py FROM ALL GET SELF
Get all callers of symX which also calls symY:
    echo symX | symrel.py GET callers WHICH call to symY
```

## Example
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
