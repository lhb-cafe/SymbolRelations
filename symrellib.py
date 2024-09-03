import sys
import re
import pickle

available_relations = {
    'call': re.compile(r'^[0-9a-f]+:\s*e8\s[ 0-9a-f]{11}\s*(call)\s+[0-9a-f]+ <(.+?)>'),
    'jump': re.compile(r'^[0-9a-f]+:\s*[0-9a-f\s]+(jmp|ja|jae|jb|jbe|jl|jle|jg|jge|jc|jnc|jo|jno|js|jns|jz|jnz)\s+[0-9a-f]+ <([^+>]*)>')
}

class Relations:
    def __init__(self):
        # index 0 for incoming, 1 for outgoing
        # a peer is a dictionary whose key is the related symbol, and value is a list of unique relation instructions
        for relation in available_relations.keys():
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

class SymbolRelations:
    def __init__(self):
        self.dict = {}
        self.instructions = list()
        self.abi_version = "v0.1"

    def get(self, sym):
        if sym not in self.dict:
            self.dict[sym] = Relations()
        return self.dict[sym]

    def register_relation(self, src, dst, rel, inst):
        if inst not in self.instructions:
            self.instructions.append(inst)
        self.get(src).add_relation(dst, rel, True, self.instructions.index(inst))
        self.get(dst).add_relation(src, rel, False, self.instructions.index(inst))

    def __find_peers_recur(self, found, src_sym, relation, forward, search, recur):
        for sym in self.get(src_sym).peers(relation, forward):
            if recur < 0: recur = -1 # negative recur means unlimited recursion
            elif recur == 0: break
            # if search is unset: Find all peers related recursively
            # if search is set:   Return immediately when it's hit
            if sym == search: # hit our target. Done
                found.clear
                found.add(sym)
                return
            if sym not in found: # needed to avoid infinite recursion
                found.add(sym)
                self.__find_peers_recur(found, sym, relation, forward, search, recur - 1)

    # if target_sym: filter the input list for peers with target_sym
    # else: find all related peers
    def search(self, in_cache, relation, forward, target_sym, recur):
        results = set()
        for sym in in_cache:
            found = set()
            self.__find_peers_recur(found, sym, relation, forward, target_sym, recur)
            if target_sym != None:
                if target_sym in found:
                    results.add(sym)
            else:
                results.update(found);
        return results

    # sym_file should be in objdump format
    def build(self, sym_file):
        self.__init__()
        src_sym = None
        func_pattern = re.compile(r'^[0-9a-f]+ <(.+?)>:')
        with open(sym_file, 'r') as file:
            for line in file:
                match = func_pattern.match(line)
                if match:
                    src_sym = match.groups()[0]
                    continue
                relation = None
                for rel, pattern in available_relations.items():
                    match = pattern.match(line)
                    if match:
                        relation = rel
                        break
                if not relation:
                    continue
                # a match of relation is found
                instruction = match.groups()[0]
                dst_sym = match.groups()[1]
                if src_sym:
                    self.register_relation(src_sym, dst_sym, relation, instruction)
                else:
                    print("Error matching relation", relation, "[None] ->", dst_sym, "without a matching caller", file=sys.stderr);
                    exit(1)

    def save(self, sr_file):
        with open(sr_file, 'wb') as file:
            pickle.dump(self, file)

    def load(self, sr_file):
        error = None
        with open(sr_file, 'rb') as file:
            sr = pickle.load(file)
        assert sr.abi_version == self.abi_version
        self.dict = sr.dict
