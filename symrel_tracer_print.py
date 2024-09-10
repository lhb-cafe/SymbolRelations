from symrel_tracer import TraceNode, RelationTraces

def str_helper(self):
    sym_str = '[' + self.symbol + ']'
    if self.selected:
        sym_str = f'[{sym_str}]'
    if self.filtered:
        sym_str = f'[{sym_str}]'
    first = (''.join([c*len(sym_str) for c in ' ']))
    second = sym_str
    if self.parent:
        step_info = ' or '.join([self.sr.instructions[idx] for idx in self.insts])

        step = ''.join([c*len(step_info) for c in '─'])
        if self.forward == None: step = '<' + step + '>'
        elif self.forward: step += '─>'
        else: step = '<─' + step
        first = ' ' + step_info + first + '  '
        second = step + ' ' + second

    if len(self.leaves) == 0:
        return ['', first, second]
    else:
        first += ' '
        if len(self.leaves) > 1:
            second += ' ┬'
        else:
            second += ' ─'
        lines = []
        lines.append('')
        lines.append(first)
        lines.append(second)

    keys = sorted(self.leaves.keys())
    leaf_lines = self.leaves[keys[0]].str_helper()
    lines[1] += leaf_lines[1]
    lines[2] += leaf_lines[2]
    paddings0 = ''.join([c*len(first) for c in ' ']) + '│'
    paddings1 = ''.join([c*len(first) for c in ' ']) + '├'
    paddings2 = ''.join([c*len(first) for c in ' ']) + '└'
    paddings3 = ''.join([c*(len(first) + 1) for c in ' '])

    for line in leaf_lines[3:]:
        lines.append(paddings0 + line)
    for key in keys[1:len(keys)-1]:
        leaf = self.leaves[key]
        cnt = 0
        for line in leaf.str_helper():
            if cnt == 2:
                lines.append(paddings1 + line)
            else:
                lines.append(paddings0 + line)
            cnt += 1
    if len(keys) > 1:
        cnt = 0
        for line in self.leaves[keys[-1]].str_helper():
            if cnt < 2:
                lines.append(paddings0 + line)
            elif cnt == 2:
                lines.append(paddings2 + line)
            else:
                lines.append(paddings3 + line)
            cnt += 1

    return lines

def __repr__(self):
    return '\n' + '\n'.join(self.str_helper()) + '\n'

TraceNode.str_helper = str_helper
TraceNode.__repr__ = __repr__
