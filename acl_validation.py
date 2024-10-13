from acl_helpers import transitive_succs, hex_hash, verify_msg
from acl_operations import PERMITTED_OPERATORS
from pprint import pprint

def precedes(ops_by_hash, hash1, hash2):
    """Checks whether op1 precedes op2.
    Assumes op1 and op2 are valid and verified messages.

    Args:
        ops_by_hash (dict[string, dict]): operation hash to operation map
        hash1 (string): hash of operation 1
        hash2 (string): hash of operation 2

    Returns:
        bool: true if op1 precedes op2, false otherwise
    """
    op2 = ops_by_hash[hash2]
    return hash1 in op2.get("deps", []) or any(
        [precedes(ops_by_hash, hash1, dep) for dep in op2.get("deps", [])]
    )


def check_graph(ops_by_hash, op_hash, added, depth):
    op = ops_by_hash[op_hash]
    
    if op_hash in depth.keys():
        return (added, depth)
    elif op["type"] == "create" and added == {} and depth == {}:
        pk = op["signed_by"]
        return ({(pk, op_hash)}, {op_hash: 0})
    elif (
        op["type"] in {"add", "remove"}
        and (deps := op.get("deps", [])) != []
        and all([dep in ops_by_hash.keys() for dep in deps])
    ):
        maxDepth = 0
        for dep in deps:
            depOp = ops_by_hash[dep]
            (added, depth) = check_graph(ops_by_hash, dep, added, depth)
            
            if added == None and depth == None:
                return (None, None)
            
            maxDepth = max(maxDepth, depth[dep])

        pk = op["signed_by"]
        possible_prevs = [prev_op for (prev_pk, prev_op) in added if prev_pk == pk]
        if not any(((pk, prev) in added and precedes(ops_by_hash, prev, op_hash)) for prev in possible_prevs):
            return (None, None)
        
        if op["type"] == "add":
            added =  added.union({(op["added_key"], op_hash)})
        
        depth[op_hash] = maxDepth +1
        return (added, depth)
    else:
        return (None, None)


def find_leaves(ops):
    in_edges = {hex_hash(op): verify_msg(op).get("deps", []) for op in ops}
    
    all_nodes = set(in_edges.keys()).union(*in_edges.values())
    
    out_nodes = set().union(*in_edges.values())
    
    leaf_nodes = all_nodes - out_nodes
    
    return list(leaf_nodes)


def compute_seniority(ops):
    """
    Compute seniority of members (pk)
    Args:
        ops (set): set of all operations

    Returns:
        dict : pk (key) - seniority (value)
    """
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}
    heads = find_leaves(ops)
    
    (added, depth) = ({}, {})
    for head in heads:
        (added, depth) = check_graph(ops_by_hash, head, added, depth)
        if added == None and depth == None:
            return (None, None)

    
    # Create ops_by_pk, where the key is the public key and the value is a set of operations.
    ops_by_pk = {}
    
    for (pk, op) in added:
        if pk not in ops_by_pk:
            ops_by_pk[pk] = set()  # Initialize an empty set for this public key
        ops_by_pk[pk].add(op)  # Add the operation to the set of operations for this public key

    # Return the public key mapped to the operation with the minimum depth and hash
    return {
        pk: (depth[op], op)  # Return a tuple (depth, hash) for the minimum op
        for pk, ops in ops_by_pk.items() 
        # Find the operation with the minimum (depth, hash) for each public key
        for op in [min(ops, key=lambda op: (depth[op], op))]
    }


def get_subject(op):
    """
    Returns the subject of an operation.
    """
    return op["signed_by"]

def authority_graph(ops):
    """
    Returns the authority graph of a set of operations.

    Args:
        ops (set): a set of operations

    Returns:
        authorityGraph: the authority graph of the operations, 
        represented as a set of edges.
        There is an edge from op1 to op2 in this graph if operation 
        op1 may affect whether op2 is authorized.
    """
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}
    auth_graph = set()
    for hash2, op2 in ops_by_hash.items():
        pk = op2["signed_by"]
        for hash1, op1 in ops_by_hash.items():
            if hash1 == hash2:
                continue
            #1)
            if ((op1["type"] == "create" and op1["signed_by"] == pk
                or op1["type"] == "add" and op1["added_key"] == pk)
                and precedes(ops_by_hash, hash1, hash2)):
                auth_graph.add((hash1, hash2))
            #2)
            if (op1["type"] == "remove" and op1["removed_key"] == pk
                and not precedes(ops_by_hash, hash2, hash1)):
                auth_graph.add((hash1, hash2))
        #3)
        if (op2["type"] == "create"):
            auth_graph.add((hash2, ("member", pk)))
        elif (op2["type"] == "add"):
            auth_graph.add((hash2, ("member", op2["added_key"])))
        elif (op2["type"] == "remove"):
            auth_graph.add((hash2, ("member", op2["removed_key"])))    

    return auth_graph

def get_member_nodes(auth_graph):
    '''
    Given the authority graph, returns member nodes
    '''

    memberNodes = set()
    for (_, n2) in auth_graph:
        if type(n2) is tuple:
            memberNodes.add(n2)
    return memberNodes


def find_cycles(auth_graph, end_ops):
    def dfs(op, path):
        if op in path:
            # Cycle detected: extract the cycle from the path
            cycle_start = path.index(op)
            return [path[cycle_start:]]  # Return the cycle as a list of lists
        else:
            cycles = []
            path.append(op)
            prevs = {n for (n, c_op) in auth_graph if c_op == op}
            for new_op in prevs:
                cycles += dfs(new_op, path.copy())
            path.pop()
            return cycles

    all_cycles = []
    # Start DFS from each node
    for op in end_ops:
        all_cycles += dfs(op, [])

    all_cycles = remove_repeated_cycles(all_cycles)
    
    return all_cycles

def remove_repeated_cycles(cycles):
    unique_cycles = set()

    for cycle in cycles:
        # Find the canonical form by rotating the cycle to start with the smallest element
        min_idx = cycle.index(min(cycle))

        #Has to be a tuple (immutable) to add to a set
        canonical_cycle = tuple(cycle[min_idx:] + cycle[:min_idx])
        
        # Add the canonical form to the set (automatically removes duplicates)
        unique_cycles.add(canonical_cycle)
    
    # Convert the set of tuples back to list of lists
    return [list(cycle) for cycle in unique_cycles]

def compute_validity(ops_by_hash: dict, auth_graph: list, op_hash, valid: set):
    '''
    Returns the set of valid operations.

    Args:
        ops_by_hash (dict): hash (key): op (val)
        auth_graph (list): list of operations 
        op: hash of current op
        valid (set): set of valid ops
    Returns:
        set of authorized operations
    '''

    if type(op_hash) is tuple:
        op = op_hash
    else:
        op = ops_by_hash[op_hash]
        if (op["type"] == "create"):
            valid.add(op_hash)
            return valid

    if op_hash in valid:
        return valid
    else:
        hash_prevs = {n for (n, c_op) in auth_graph if c_op == op_hash}
        for prev in hash_prevs:
            valid = compute_validity(ops_by_hash, auth_graph, prev, valid)
        #get all valid previous nodes
        valid_predecessors = {n for n in hash_prevs if n in valid}
        #if precedes(ops_by_hash, v, op_hash)
        if is_op_valid(ops_by_hash, valid_predecessors, op):
            valid.add(op_hash)
        return valid
        

def is_op_valid(ops_by_hash, valid_predecessors, op):
    '''
    op to be valid iff there is at least one add or create operation 
    in the set in that has not been overridden by a
    subsequent remove operation: in other words, if the device that 
    generated op has been added to the group and not yet
    been removed again
    '''

    if (type(op) is tuple):
        subject = op[1]
    else:
        subject = get_subject(op)
    
    for op_x_hash in valid_predecessors:
        op_x = ops_by_hash[op_x_hash]
        #if it is not an add or a create keep going
        if not ((op_x["type"] == "add" and op_x["added_key"] == subject) 
            or (op_x["type"] == "create" and op_x["signed_by"] == subject)):
            continue

        #if it is, check if there is no remove after
        add_valid = True
        for op_y_hash in valid_predecessors:
            op_y = ops_by_hash[op_y_hash]
            #get all removes
            if (op_y["type"] == "remove" and op_y["removed_key"] == subject):
                #if there exists one remove after the
                if precedes(ops_by_hash, op_x_hash, op_y_hash):
                    add_valid = False
                    break

        #If there was no remove after the add, the op is valid
        if add_valid:
            return True

    #There was no valid add
    return False


def compute_membership(ops):
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}

    seniority_dict = compute_seniority(ops)

    if (seniority_dict == (None, None)):
        raise Exception("Graph is not correct")
    
    auth_graph = authority_graph(ops)
    member_nodes = get_member_nodes(auth_graph)

    cycles = find_cycles(auth_graph, member_nodes)

    drop = set()
    for cycle in cycles:
        drop.add(max(cycle, key= lambda x : seniority_dict.get(get_subject(ops_by_hash[x]))))

    auth_graph = {(n1, n2) for (n1, n2) in auth_graph if (n1 not in drop) and (n2 not in drop)}

    valid = set()

    for member in member_nodes:
        valid.union(compute_validity(ops_by_hash, auth_graph, member, valid))

    return {member[1] for member in member_nodes if member in valid}