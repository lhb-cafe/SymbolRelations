from symrel_tracer import TraceNode, RelationTraces
from symrel_tracer_verify import verify_ret_with, verify_node
import sys, os

def supports_color():
    # TODO: color is not vim-friendly
    #return sys.stdout.isatty() and os.getenv('TERM') in ['xterm', 'xterm-256color', 'screen', 'screen-256color']
    return False

def compute_leaves(self):
    if hasattr(self, 'leaves_cnt'):
        return self.leaves_cnt
    else:
        self.leaves_cnt = 1
        for leaf in self.leaves.values():
            self.leaves_cnt += compute_leaves(leaf)
        return self.leaves_cnt

def str_helper(self, color):
    green_color = '\033[92m'
    blue_color = '\033[94m'
    reset_color = '\033[0m'

    sym_str = '[' + self.symbol + ']'
    sym_str_len = len(sym_str)
    if hasattr(self, 'flag_for_selected'):
        del self.flag_for_selected
        if color:
            sym_str = f'{green_color}{sym_str}{reset_color}'
        else:
            sym_str = f'[{sym_str}]'
            sym_str_len += 2
    if self.filtered:
        compute_leaves(self.filter_trace)
        leaves = sorted(list(self.filter_trace.leaves.values()))
    else:
        leaves = []
    first = ''.join([c*sym_str_len for c in ' '])
    second = sym_str

    if self.parent:
        inst_str_list = []
        for inst in self.insts:
            if isinstance(self.sr.instructions[inst], tuple):
                # inst is wrapped with offset info
                real_ind = self.sr.instructions[inst][0]
                offset = self.sr.instructions[inst][1]
                inst_str_list.append(f'{self.sr.instructions[real_ind]} at +{offset}')
            else:
                inst_str_list.append(self.sr.instructions[inst])
        step_info = ' or '.join(inst_str_list)

        step = ''.join([c*len(step_info) for c in '-'])
        if self.forward == None: step = '<' + step + '>'
        elif self.forward: step += '->'
        else: step = '<-' + step
        first = ' ' + step_info + first + '  '
        second = step + ' ' + second

    leaves += sorted(list(self.leaves.values()))
    if len(leaves) == 0:
        lines = ['', first, second]
    else:
        first += '  '
        if len(leaves) > 1:
            second += ' ┬'
        else:
            second += ' -'
        lines = []
        lines.append('')
        lines.append(first)
        lines.append(second)

        leaf_lines = leaves[0].str_helper(color)
        lines[1] += leaf_lines[1]
        lines[2] += leaf_lines[2]
        paddings0 = ''.join([c*(len(first) - 1) for c in ' ']) + '│'
        paddings1 = ''.join([c*(len(first) - 1) for c in ' ']) + '├'
        paddings2 = ''.join([c*(len(first) - 1) for c in ' ']) + '└'
        paddings3 = ''.join([c*len(first) for c in ' '])

        for line in leaf_lines[3:]:
            if len(leaves) > 1:
                lines.append(paddings0 + line)
            else:
                lines.append(paddings3 + line)
        for leaf in leaves[1:len(leaves)-1]:
            cnt = 0
            for line in leaf.str_helper(color):
                if cnt == 2:
                    lines.append(paddings1 + line)
                else:
                    lines.append(paddings0 + line)
                cnt += 1
        if len(leaves) > 1:
            cnt = 0
            for line in leaves[-1].str_helper(color):
                if cnt < 2:
                    lines.append(paddings0 + line)
                elif cnt == 2:
                    lines.append(paddings2 + line)
                else:
                    lines.append(paddings3 + line)
                cnt += 1

    if color and hasattr(self, 'is_filter_trace'):
        for i in range(0, len(lines)):
            lines[i] = blue_color + lines[i] + reset_color
    return lines

def __repr__(self):
    compute_leaves(self)
    return '\n' + '\n'.join(self.str_helper(supports_color())) + '\n'

def node_compare(self, other):
    if self.leaves_cnt != other.leaves_cnt:
        return self.leaves_cnt > other.leaves_cnt
    else:
        return self.symbol > other.symbol

@verify_ret_with(verify_node)
def invert_node(self):
    root = TraceNode(self.symbol, sr = self.sr)
    cur = root
    leaf = self
    while True:
        if leaf.filtered:
            cur.filtered = True
            # this is only used for printing, don't bother copying
            cur.filter_trace = leaf.filter_trace

        if not leaf.parent:
            break
        new_leaf = TraceNode(leaf.parent.symbol, sr = self.sr)
        new_leaf.insts = leaf.insts
        if leaf.forward != None:
            new_leaf.forward = not leaf.forward
        else:
            new_leaf.forward = None

        ref = cur.add_leaf(new_leaf)
        assert not ref[new_leaf.symbol] is new_leaf
        cur = new_leaf
        leaf = leaf.parent
    return root

TraceNode.str_helper = str_helper
TraceNode.__repr__ = __repr__
TraceNode.invert = invert_node
TraceNode.__lt__ = node_compare

# take a list of leaves with the same symbol and build a reverse TraceNode
@verify_ret_with(verify_node)
def build_reverse_node(symbol, leaves, sr):
    root = TraceNode(symbol, sr = sr)
    root.flag_for_selected = True
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

    # flag nodes in self.leaves as selected
    for nodes in self.leaves.values():
        for node in nodes:
            node.flag_for_selected = True

    if not backward:
        for sym in show_cache:
            print(self.roots[sym])
        return

    # print backward traces from cache
    for sym in show_cache:
        print(build_reverse_node(sym, self.leaves[sym], self.sr))

RelationTraces.print = trace_print
