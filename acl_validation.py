from acl_helpers import transitive_succs, hex_hash, verify_msg
from acl_operations import PERMITTED_OPERATORS

def validate_op_types(parsed_ops):
    if any(op["type"] not in PERMITTED_OPERATORS for op in parsed_ops):
        raise Exception("Every op must be either create, add, remove or message")

    if any("added_key" not in op for op in parsed_ops if op["type"] == "add"):
        raise Exception("Every add operation must have an added_key")
    if any("removed_key" not in op for op in parsed_ops if op["type"] == "remove"):
        raise Exception("Every remove operation must have a removed_key")


def validate_hash_graph(ops_by_hash, parsed_ops):
    if any(len(op["deps"]) == 0 for op in parsed_ops if op["type"] != "create"):
        raise Exception("Every non-create op must have at least one predecessor")
    if any(
        pred not in ops_by_hash
        for op in parsed_ops
        if op["type"] != "create"
        for pred in op["deps"]
    ):
        raise Exception("Every hash must resolve to another op in the set")


def get_successors_per_op(ops_by_hash):
    successors = {}
    for hash, op in ops_by_hash.items():
        for pred in op.get("deps", []):
            successors[pred] = successors.get(pred, set()) | {hash}

    return successors


def get_creation_op(ops_by_hash):
    create_ops = [
        (hash, op) for hash, op in ops_by_hash.items() if op["type"] == "create"
    ]
    if len(create_ops) != 1:
        raise Exception("There must be exactly one create operation")

    return create_ops[0]


def compute_members(ops_by_hash, successors):
    members = set()
    for hash, op in ops_by_hash.items():
        if op["type"] in {"create", "add"}:
            added_key = op["signed_by"] if op["type"] == "create" else op["added_key"]
            succs = [ops_by_hash[succ] for succ in transitive_succs(successors, hash)]
            if not any(
                succ["type"] == "remove" and succ["removed_key"] == added_key
                for succ in succs
            ):
                members.add(added_key)

    return members


def interpret_ops(ops):
    """
    Takes a set of access control operations and computes the currently authorised set of users.
    Throws an exception if something isn't right.
    """

    # Check all the signatures and parse all the JSON
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}
    parsed_ops = ops_by_hash.values()

    # Every op must be one of the expected types
    validate_op_types(parsed_ops)

    # Hash graph integrity: every op except the initial creation must reference at least one
    # predecessor operation, and all predecessors must exist in the set
    validate_hash_graph(ops_by_hash, parsed_ops)

    # Get the set of successor hashes for each op
    successors = get_successors_per_op(ops_by_hash)

    # Get the public key of the group creator and creation operation
    create_hash, create_op = get_creation_op(ops_by_hash)

    # Only the group creator may sign add/remove ops (TODO: change this!)
    if any(op["signed_by"] != create_op["signed_by"] for op in parsed_ops):
        raise Exception("Only the group creator may sign add/remove operations")

    # Current group members are those who have been added, and not removed again by a remove
    # operation that is a transitive successor to the add operation.
    members = compute_members(ops_by_hash, successors)

    return members


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


def check_graph(ops_by_hash, op, added, depth):
    """_summary_

    Args:
        ops_by_hash (_type_): _description_
        op (_type_): _description_
        added (_type_): _description_
        depth (_type_): _description_

    Returns:
        _type_: _description_
    """
    if op in depth:
        return (added, depth)
    elif op["type"] == "create" and added == {} and depth == {}:
        pk = op["signed_by"]
        return ({(pk, op)}, {op: 0})
    elif (
        op["type"] in {"add", "remove"}
        and (deps := op.get("deps", [])) != []
        and all([dep in ops_by_hash.keys() for dep in deps])
    ):
        maxDepth = 0
        for dep in deps:
            depOp = ops_by_hash[dep]
            (added, depth) = check_graph(ops_by_hash, depOp, added, depth)
            
            if added == None and depth == None:
                return (None, None)
            
            maxDepth = max(maxDepth, depth[depOp])

        pk = op["signed_by"]
        possible_prevs = [] #TODO:how tf do I get this??
        if not any((pk, prev) in added and precedes(ops_by_hash, prev, op) for prev in possible_prevs):
            return (None, None)
        
        if op["type"] == "add":
            added =  added.union({(op["added_key"], op)})
        
        depth[op] = maxDepth +1
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
    """_summary_

    Args:
        ops (_type_): _description_

    Returns:
        _type_: _description_
    """
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}
    heads = find_leaves(ops)
    
    (added, depth) = ({}, {})
    for head in heads:
        (added, depth) = check_graph(ops_by_hash, head, added, depth)
        if added == None and depth == None:
            return (None, None)

    
    ops_by_pk = {pk: a.get(pk, {}).union(op) for (pk, op) in added}
    return {pk: min(ops, key=lambda op: (depth[op], hex_hash(op))) for (pk, ops) in ops_by_pk}

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

def compute_validity(ops_by_hash: dict, auth_graph: list, op, valid: set):
    '''
    Returns the set of valid operations.

    Args:
        ops_by_hash (dict): hash (key): op (val)
        auth_graph (list): list of operations 
        op: current op
        valid (set): set of valid ops
    Returns:
        set of authorized operations
    '''
    #members = get_member_nodes(auth_graph)
    if op in valid:
        return valid
    elif op["type"] == "create":
        #may give error with member
        #op not in members and
        valid.add(op)
        return valid
    else:
        prevs = {n for (n, c_op) in auth_graph if c_op == op}
        for prev in prevs:
            valid = compute_validity(ops_by_hash, auth_graph, prev, valid)
        #get all valid previous nodes
        valid_predecessors = {v for v in valid if precedes(ops_by_hash, v, op)}
        if is_op_valid(ops_by_hash, valid_predecessors, op):
            valid.add(op)
        return valid
        

def is_op_valid(ops_by_hash, valid_predecessors, op):
    '''
    op to be valid iff there is at least one add or create operation 
    in the set in that has not been overridden by a
    subsequent remove operation: in other words, if the device that 
    generated op has been added to the group and not yet
    been removed again
    '''

    #TODO: TEST 
    
    subject = get_subject(op)
    
    for op_x in valid_predecessors:

        #if it is not an add or a create keep going
        if not ((op_x["type"] == "add" and op_x["added_key"] == subject) 
            or (op_x["type"] == "create" and op_x["signed_key"] == subject)):
            continue

        #if it is, check if there is no remove after
        add_valid = True
        for op_y in valid_predecessors:
            #get all removes
            if (op_y["type"] == "remove" and op_y["remove_key"] == subject):
                #if there exists one remove after the
                if precedes(ops_by_hash, op_x, op_y):
                    add_valid = False
                    break

        #If there was no remove after the add, the op is valid
        if add_valid:
            return True

    #There was no valid add
    return False