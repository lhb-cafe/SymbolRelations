from symrel_tracer_verify import verify_self_with, verify_ret_with, verify_traces
from symrel_tracer import TraceNode, RelationTraces

def WrapBinaryOps(type, ops_dict):
    def decorator(cls):
        def gen_op(op, method):
            return lambda self, other: getattr(cls, method)(self, other, getattr(type, op))
        for ops, method in ops_dict.items():
            for op in ops:
                setattr(cls, op, gen_op(op, method))
        return cls
    return decorator

@verify_self_with(verify_traces)
def __set_iop__(self, other, iop):
    self.cache = iop(self.cache, other.cache)
    if not self.tracing:
        return self
    assert other.tracing

    new_leaves = dict()
    # joining the roots
    for sym, root in other.roots.items():
        if sym not in self.roots:
            self.roots[sym] = root
            root.get_leaves(new_leaves)
        else:
            self.roots[sym].join(root, new_leaves = new_leaves, self_leaves = self.leaves, other_leaves = other.leaves)

    # content of other becomes irrelevant in our use cases so don't bother copying it
    # this will raise a failure in verify_traces if other ever got used again
    other.roots.clear()
    other.roots['intended_failure'] = TraceNode()

    # merging the new_leaves
    RelationTraces.merge_leaves(self.leaves, new_leaves)

    self.trim_traces()
    return self

@verify_ret_with(verify_traces)
def __set_op__(self, other, op):
    ret = self.copy_traces(copy_cache = True)
    # should have translated op to iop, but the result will be the same (maybe slower)
    return ret.__set_iop__(other, op)


set_ops_mapping = {
    ('__and__',  '__or__',  '__sub__'):  '__set_op__',
    ('__iand__', '__ior__', '__isub__'): '__set_iop__'
}

RelationTraces.__set_iop__ = __set_iop__
RelationTraces.__set_op__ = __set_op__
RelationTraces = WrapBinaryOps(set, set_ops_mapping)(RelationTraces)
