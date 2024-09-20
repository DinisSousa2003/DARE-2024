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


def precedes(ops_by_hash, op1, op2):
    """Checks whether op1 precedes op2.
    Assumes op1 and op2 are valid and verified messages.

    Args:
        ops_by_hash (dict[string, dict]): operation hash to operation map
        op1 (dict): operation 1
        op2 (dict): operation 2

    Returns:
        bool: true if op1 precedes op2, false otherwise
    """
    return hex_hash(op1) in op2.get("deps", []) or any(
        [precedes(ops_by_hash, op1, ops_by_hash[dep]) for dep in op2.get("deps", [])]
    )


def checkGraph(ops_by_hash, op, added, depth):
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
            (added, depth) = checkGraph(ops_by_hash, depOp, added, depth)
            
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


def computeSeniority(ops):
    """_summary_

    Args:
        ops (_type_): _description_

    Returns:
        _type_: _description_
    """
    ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}
    #heads = ??
    
    (added, depth) = ({}, {})
    for head in heads:
        (added, depth) = checkGraph(ops_by_hash, head, added, depth)
        if added == None and depth == None:
            return (None, None)

    
    ops_by_pk = {pk: a.get(pk, {}).union(op) for (pk, op) in added}
    return {pk: min(ops, key=lambda op: (depth[op], hex_hash(op))) for (pk, ops) in ops_by_pk}
