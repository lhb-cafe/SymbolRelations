from symrel_tracer import TraceNode, RelationTraces
from symrel_tracer_verify import verify_ret_with, verify_node
import sys, os

def supports_color():
    return sys.stdout.isatty() and os.getenv('TERM') in ['xterm', 'xterm-256color', 'screen', 'screen-256color']

def str_helper(self, color):
    selected_color = '\033[92m' # green
    reset_color = '\033[0m'

    sym_str = '[' + self.symbol + ']'
    sym_str_len = len(sym_str)
    if self.selected:
        if color:
            sym_str = f'{selected_color}{sym_str}{reset_color}'
        else:
            sym_str = f'[{sym_str}]'
            sym_str_len += 2
    if self.filtered:
        sym_str = f'[{sym_str}]'
    first = ''.join([c*sym_str_len for c in ' '])
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
        first += '  '
        if len(self.leaves) > 1:
            second += ' ┬'
        else:
            second += ' ─'
        lines = []
        lines.append('')
        lines.append(first)
        lines.append(second)

    keys = sorted(self.leaves.keys())
    leaf_lines = self.leaves[keys[0]].str_helper(color)
    lines[1] += leaf_lines[1]
    lines[2] += leaf_lines[2]
    paddings0 = ''.join([c*(len(first) - 1) for c in ' ']) + '│'
    paddings1 = ''.join([c*(len(first) - 1) for c in ' ']) + '├'
    paddings2 = ''.join([c*(len(first) - 1) for c in ' ']) + '└'
    paddings3 = ''.join([c*len(first) for c in ' '])

    for line in leaf_lines[3:]:
        if len(keys) > 1:
            lines.append(paddings0 + line)
        else:
            lines.append(paddings3 + line)
    for key in keys[1:len(keys)-1]:
        leaf = self.leaves[key]
        cnt = 0
        for line in leaf.str_helper(color):
            if cnt == 2:
                lines.append(paddings1 + line)
            else:
                lines.append(paddings0 + line)
            cnt += 1
    if len(keys) > 1:
        cnt = 0
        for line in self.leaves[keys[-1]].str_helper(color):
            if cnt < 2:
                lines.append(paddings0 + line)
            elif cnt == 2:
                lines.append(paddings2 + line)
            else:
                lines.append(paddings3 + line)
            cnt += 1

    return lines

def __repr__(self):
    return '\n' + '\n'.join(self.str_helper(supports_color())) + '\n'

@verify_ret_with(verify_node)
def invert_node(self):
    root = TraceNode(self.symbol, sr = self.sr)
    cur = root
    leaf = self
    while leaf.parent:
        new_leaf = TraceNode(leaf.parent.symbol, sr = self.sr)
        new_leaf.insts = leaf.insts
        if leaf.forward != None:
            new_leaf.forward = not leaf.forward
        else:
            new_leaf.forward = None
        if leaf.filtered:
            new_leaf.filtered = True
            # this is only used for printing, don't bother copying
            new_leaf.filter_trace = leaf.filter_trace

        ref = cur.add_leaf(new_leaf)
        assert not ref[new_leaf.symbol] is new_leaf
        cur = new_leaf
        leaf = leaf.parent
    return root

TraceNode.str_helper = str_helper
TraceNode.__repr__ = __repr__
TraceNode.invert = invert_node

# take a list of leaves with the same symbol and build a reverse TraceNode
@verify_ret_with(verify_node)
def build_reverse_node(symbol, leaves, sr):
    root = TraceNode(symbol, sr = sr, selected = True)
    for node in leaves:
        root.join(node.invert())
    return root

def trace_print(self, cache = None, backward = False):
    if backward or not self.tracing:
        show_cache = self.cache
    else:
        show_cache = set(self.roots.keys())

    if cache != None:
        show_cache &= cache
    show_cache = sorted(show_cache)

    if not self.tracing:
        for sym in show_cache:
            print(sym)
        return

    if not backward:
        for sym in show_cache:
            print(self.roots[sym])
        return

    # print backward traces from cache
    for sym in show_cache:
        print(build_reverse_node(sym, self.leaves[sym], self.sr))

RelationTraces.print = trace_print
