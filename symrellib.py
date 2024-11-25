import sys
import os
import pickle
from importlib import import_module
from symrel_tracer import TraceNode, RelationTraces

static_relations = None

class Relations:
    def __init__(self):
        # index 0 for incoming, 1 for outgoing
        # a peer is a dictionary whose key is the related symbol, and value is a list of unique relation instructions
        for relation in static_relations:
            setattr(self, relation, (dict(), dict()))

    def peers(self, relation, forward):
        return getattr(self, relation)[forward]

    def add_relation(self, other, relation, forward, inst_index):
        peers = self.peers(relation, forward)
        if other in peers:
            if inst_index not in peers[other]:
                peers[other].append(inst_index)
        else:
            peers[other] = [inst_index]

    def add_relation_batch(self, others, relation, forward, inst_index):
        peers = self.peers(relation, forward)
        if other in peers:
            if inst_index not in peers[other]:
                peers[other].append(inst_index)
        else:
            peers[other] = [inst_index]

class SymbolRelations:
    def __init__(self):
        self.dict = {}
        self.instructions = list()
        self.tracing = False
        self.search_history = []
        self.abi_version = "v0.3"
        self.arch = None
        sys.path.append(os.path.abspath('./parser'))

    def get(self, sym):
        if sym not in self.dict:
            self.dict[sym] = Relations()
        return self.dict[sym]

    def register_relation(self, src, dst, rel, inst, offset):
        if inst not in self.instructions:
            self.instructions.append(inst)
        # wrap offset inside inst
        raw_inst_ind = self.instructions.index(inst)
        inst = (raw_inst_ind, offset)
        if inst not in self.instructions:
            self.instructions.append(inst)
        self.get(src).add_relation(dst, rel, True, self.instructions.index(inst))
        self.get(dst).add_relation(src, rel, False, self.instructions.index(inst))

    def declare_dynamic_rel(self, new_rel):
        assert new_rel not in self.instructions
        self.instructions.append(new_rel)
        self.available_relations.append(new_rel)
        for symrels in self.dict.values():
            setattr(symrels, new_rel, (dict(), dict()))

    def add_dynamic_rel(self, src, dst_set, new_rel):
        index = self.instructions.index(new_rel)
        for dst in dst_set:
            self.get(src).add_relation(dst, new_rel, True, index)
            self.get(dst).add_relation(src, new_rel, False, index)

    def __find_peers_recur(self, found, src_sym, relation, forward, search, recur):
        if src_sym not in self.dict:
            print(f'hit undefined symbol [{src_sym}]')
            return
        if recur < 0: recur = -1 # negative recur means unlimited recursion

        recur_list = []
        for sym, inst_index_list in self.get(src_sym).peers(relation, forward).items():
            if found.add_step(sym, src_sym, tuple(inst_index_list), forward):
                recur_list.append(sym)
            else:
                continue
            # if search is unset: Find all peers related recursively
            # if search is set:   Return immediately when it's hit, unless tracing is True,
            #                     in which case the search continues to find all traces
            if sym == search and not self.tracing: # hit our target. Done
                found.commit()
                return
        # BFS
        if len(recur_list) > 0:
            found.commit()
            if recur > 1:
                for sym in recur_list:
                    self.__find_peers_recur(found, sym, relation, forward, search, recur - 1)
        else:
            # nothing added for this symbol, return before we hit an infinite loop
            return

    # if target_sym: filter the input list for peers with target_sym
    # else: find all related peers
    def search(self, in_cache, relation, forward, target_sym, recur):
        assert isinstance(in_cache, RelationTraces)
        results = in_cache.copy_traces()
        for sym in in_cache:
            found = self.build_cache({sym}, trace_only = True)
            self.__find_peers_recur(found, sym, relation, forward, target_sym, recur)
            if target_sym != None:
                if target_sym in found:
                    if self.tracing:
                        # we only need the trace to target_sym
                        found.trim_traces({target_sym})
                        results.add_filter(sym, found.roots[sym])
                    else:
                        results.cache.add(sym)
            else:
                found.trim_traces()
                results.add_traces(found)
        results.commit()
        return results

    def set_tracing(self, tracing):
        self.tracing = tracing

    def set_arch(self, arch):
        self.arch = arch

    def build(self, filepath):
        assert self.arch != None
        with open(filepath, 'rb') as file:
            magic = file.read(4)
            if magic == b'\x7f\x45\x4c\x46':
                arch_parser = import_module(f'{self.arch}_elf')
            else:
                print('not ELF file, assuming objdump format...')
                arch_parser = import_module(f'{self.arch}_objdump')

        self.available_relations = arch_parser.relations
        global static_relations
        static_relations = self.available_relations
        return arch_parser.parse(self, filepath)

    def build_cache(self, symbols = None, trace_only = False):
        return RelationTraces(self, symbols, trace_only, tracing = self.tracing)

    def save(self, sr_file):
        self.build = None
        with open(sr_file, 'wb') as file:
            pickle.dump(self, file)

    def load(self, sr_file):
        error = None
        with open(sr_file, 'rb') as file:
            sr = pickle.load(file)
        assert sr.abi_version == self.abi_version
        self.__dict__.update(sr.__dict__)
