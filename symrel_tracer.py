import copy
from symrel_tracer_verify import verify_self_with, verify_ret_with, verify_node, verify_traces

class TraceNode:
    @verify_self_with(verify_node)
    def __init__(self, symbol = None, insts = None, forward = None, selected = False, leaves = [], parent = None, sr = None):
        self.sr = sr
        self.symbol = symbol
        self.insts = insts
        self.forward = forward
        self.parent = parent
        self.leaves = dict()
        self.selected = selected
        self.filtered = False
        for node in leaves:
            self.add_leaf(node)

    # return a dictionary mappeing symbols to references of last touched leaves
    @verify_self_with(verify_node)
    def add_leaf(self, other):
        leaves = dict()
        if (other.symbol, other.forward) in self.leaves:
            self.leaves[(other.symbol, other.forward)].join(other, leaves)
            return leaves
        else:
            other.get_leaves(leaves)
            other.parent = self
            self.leaves[(other.symbol, other.forward)] = other
        return leaves

    # add trace from other to self
    # self uses reference directly from other without copying
    @verify_self_with(verify_node)
    def join(self, other, leaves = None):
        assert self.symbol == other.symbol
        self.selected |= other.selected
        # joining filter info
        if other.filtered:
            if self.filtered:
                self.filter_trace.join(other.filter_trace)
            else:
                self.filter_trace = other.filter_trace
        # joining insts tuple
        if other.insts and self.insts != other.insts:
            self.insts = tuple(sorted(set(self.insts + other.insts)))

        for o_tuple, o_node in other.leaves.items():
            if o_tuple in self.leaves:
                s_node = self.leaves[o_tuple].join(o_node, leaves)
            else:
                if leaves != None:
                    o_node.get_leaves(leaves)
                self.add_leaf(o_node)

    def get_leaves(self, leaves):
        if len(self.leaves) == 0:
            if self.symbol in leaves:
                leaves[self.symbol].append(self)
            else:
                leaves[self.symbol] = [self]
        else:
            for node in self.leaves.values():
                node.get_leaves(leaves)

    # this works for siblings only, which are guaranteed to have different (symbol, forward) pairs
    def __lt__(self, other):
        if self.symbol != other.symbol:
            return self.symbol < other.symbol
        else:
            assert self.forward != other.forward
            return self.forward < other.forward

    @verify_ret_with(verify_node)
    def __deepcopy__(self, memo):
        ret = type(self)(self.symbol, self.insts, self.forward, self.selected, parent = self.parent, sr = self.sr)
        ret.filtered = self.filtered
        if self.filtered:
            ret.filter_trace = self.filter_trace.__deepcopy__(memo)
        memo[id(self)] = ret

        for tuple, node in self.leaves.items():
            new_node = node.__deepcopy__(memo)
            ret.leaves[tuple] = new_node
            new_node.parent = ret
        return ret

class RelationTraces():
    @verify_self_with(verify_traces)
    def __init__(self, sr, symbols = None, clear_cache = False, tracing = False):
        assert sr != None
        self.sr = sr
        # should be a subset of self.leaves.keys(), used to trim down trace
        self.cache = set()
        self.staged_cache = set() # uncommitted changes
        if symbols and not clear_cache:
            assert isinstance(symbols, set)
            self.cache = symbols
        self.tracing = tracing
        if not tracing:
            return

        # map a symbol to the trace root that starts with it
        self.roots = dict()
        # maps a symbol to all trace leaf that ends with it
        self.leaves = dict()
        self.staged_leaves = dict() # uncommitted changes
        # initialize the input symbols as trace roots (and leaf at the same time)
        if symbols:
            for sym in symbols:
                node = TraceNode(sym, selected = True, sr = self.sr)
                self.roots[sym] = node
                self.leaves[sym] = [node]

    @classmethod
    def merge_leaves(cls, s_leaves, o_leaves):
        for sym, nodes in o_leaves.items():
            if sym in s_leaves:
                s_leaves[sym] += [node for node in nodes if node not in s_leaves[sym]]
            else:
                s_leaves[sym] = nodes

    # return True if an actual update got staged
    def add_step(self, dst_sym, src_sym, inst_tuple = None, forward = None, filter_trace = None):
        updated = False
        if dst_sym not in self.cache and dst_sym not in self.staged_cache:
            self.staged_cache.add(dst_sym)
            updated = True

        # sanity checks for tracing
        if not self.tracing:
            return updated
        elif dst_sym in self.leaves:
            for node in self.leaves[dst_sym]:
                if node.parent == src_sym and set(inst_tuple).issubset(set(node.inst_tuple)):
                    # this step already exists, no need to add anything
                    return updated
        assert src_sym in self.leaves and len(self.leaves[src_sym]) > 0
        if dst_sym not in self.staged_leaves:
            self.staged_leaves[dst_sym] = []

        # create the new node and handle tracing
        new = TraceNode(dst_sym, inst_tuple, forward, sr = self.sr)
        if filter_trace:
            assert dst_sym == src_sym
            new.filtered = True
            new.filter_trace = filter_trace
        for src_node in self.leaves[src_sym]:
            if new.filtered:
                # dst_sym is the same as src_sym, unselect the duplicated src node
                src_node.selected = False
            RelationTraces.merge_leaves(self.staged_leaves, src_node.add_leaf(copy.copy(new)))
        return True

    # we should have copied the objects from other, but in our uses cases it doesn't really matter
    # appends other's traces to self's staged lists
    def add_traces(self, other):
        self.staged_cache |= other.cache
        if not self.tracing:
            return self

        # append other's roots to self's leaves
        for sym, o_node in other.roots.items():
            for s_node in self.leaves[sym]:
                # s_node and o_node has the same symbol
                s_node.join(o_node)

        RelationTraces.merge_leaves(self.staged_leaves, other.leaves)
        return self

    @verify_self_with(verify_traces)
    def commit(self):
        # merge cache
        self.cache |= self.staged_cache
        self.staged_cache = set()
        if not self.tracing:
            return self

        # remove unselected nodes from self.leaves
        for sym, nodes in self.leaves.items():
            self.leaves[sym] = [node for node in nodes if node.selected]
        # mark staged leaves as selected and merge leaves
        for sym, nodes in self.staged_leaves.items():
            for node in nodes: node.selected = True
        RelationTraces.merge_leaves(self.leaves, self.staged_leaves)
        self.staged_leaves = dict()
        self.trim_traces()

    # keep only the traces ending with symbols in cache
    # effectively making self.leaves.keys() the same set as self.cache
    @verify_self_with(verify_traces)
    def trim_traces(self, cache = None):
        if cache:
            self.cache &= cache
        if not self.tracing:
            return

        # trim from leaves
        for garbage in set(self.leaves.keys()) - self.cache:
            nodes = self.leaves.pop(garbage)
            while len(nodes) > 0:
                node = nodes.pop()
                if len(node.leaves) > 0:
                    # don't remove if not actual leaf, simply unselect it
                    node.selected = False
                    continue
                # trace backward until we hit a branch or an end
                while node.parent and len(node.parent.leaves) == 1:
                    node = node.parent
                if node.parent == None:
                    # node is in self.roots. Release it
                    assert node is self.roots[node.symbol]
                    del self.roots[node.symbol]
                else:
                    # release from parent
                    assert node is node.parent.leaves[(node.symbol, node.forward)]
                    del node.parent.leaves[(node.symbol, node.forward)]

    @verify_ret_with(verify_traces)
    def copy_traces(self, copy_cache = False):
        ret = type(self)(self.sr, tracing = self.tracing)
        if copy_cache:
            ret.cache = copy.copy(self.cache)

        if ret.tracing:
            memo = dict()
            ret.roots = copy.deepcopy(self.roots, memo)
            ret.leaves = copy.deepcopy(self.leaves, memo)
        return ret

    def __iter__(self):
        return self.cache.__iter__()

import symrel_tracer_print
import symrel_tracer_ops