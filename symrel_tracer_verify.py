verify_on = False # this would slow things down
record_arg = False # this would slow things down further by building the __repr__ for nodes

def __verify_with(verify_func, object):
    def decorator(method):
        if not verify_on:
            return method

        def wrapper(self, *args, **kwargs):
            if record_arg:
                call_str =  f'{method.__name__}{(self,) + args}' # TODO: kwargs
            else:
                call_str = method.__name__

            retval = method(self, *args, **kwargs)
            verify_obj = locals()[object]
            if verify_func(verify_obj) == False:
                print("\nverification faild after calling:", call_str)
                print('verification history:\n', verify_obj.verify_history, '\n')
                assert False

            if not hasattr(verify_obj, 'verify_history'):
                verify_obj.verify_history = []
            verify_obj.verify_history.append(method.__name__)
            return retval
        return wrapper
    return decorator

def verify_self_with(verify_func):
    return __verify_with(verify_func, 'self')

def verify_ret_with(verify_func):
    return __verify_with(verify_func, 'retval')

def verify_node(self):
    if self.filtered:
        if not hasattr(self, 'filter_trace'):
            print("filter_trace is missing for a filtered node:\n", self)
            return False
    elif self.parent:
        if self.insts == None or self.forward == None:
            print("Missing insts or forward\n")
            return False
    return True

# check if all leaves of node fall into leaves (second arg)
def __verify_leaves(node, leaves):
    if len(node.leaves) == 0:
        if node.symbol not in leaves or node not in leaves[node.symbol]:
            return False, node
        return True, None
    for leaf in node.leaves.values():
        ret, node = __verify_leaves(leaf, leaves)
        if ret == False:
            return False, node
    return True, None

def verify_traces(self):
    if not self.tracing:
        return True
    success = True
    # check that all leaves from self.roots fall into self.leaves
    for sym, root in self.roots.items():
        ret, bad_node = __verify_leaves(root, self.leaves)
        if ret == False:
            print(f'bad root:\n{root}\n\nwith a bad leaf no in self.leaves:\n{bad_node}\n\navailable self.leaves:')
            if bad_node.symbol in self.leaves:
                for node in self.leaves[bad_node.symbol]: print(node)
            print('\n\n')
            return False
        if not verify_node(root):
            print(f'Not a valid root:\n{root}\n\n')
            return False
    # check that all nodes in self.leaves are either actual leaves themself
    # or have at least one leaf also in self.leaves
    for sym, nodes in self.leaves.items():
        seen = []
        for node in nodes:
            if len(node.leaves) > 0:
                found = False
                for leaf in node.leaves.values():
                    if leaf in self.leaves[leaf.symbol]:
                        found = True
                if not found:
                    print(f'bad leaf (has leaf not in self.leaves) with {sym}:\n{node}')
                    success = False

            if node in seen:
                print(f'bad leaf (duplicated) with {sym}:\n{node}\n\navailable leaves:')
                for node in self.leaves[sym]: print(node)
                success = False
            seen.append(node)

            while node.parent:
                node = node.parent

            # check all root traced back from self.leaves lives in self.roots
            if not success:
                print(f'from root:\n{node}')
                return False
            if not node.symbol in self.roots or not node is self.roots[node.symbol]:
                print(f'bad leaf (cannot trace back to roots) with {sym}:\n{node}')
                return False
    return success
