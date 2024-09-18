from acl_helpers import transitive_succs, hex_hash, verify_msg
from acl_operations import PERMITTED_OPERATORS


def is_op_valid(hash, ops_by_hash):
    """
    Takes the hash of a node operation and sees if the actor of the operation was valid
    """

    current_op = ops_by_hash.get(hash)

    if current_op["type"] in {"add", "remove", "message"}:

        # DO A TOPOLOGICAL SORT

        pass


def validate_op_types(parsed_ops):
    if any(op["type"] not in PERMITTED_OPERATORS for op in parsed_ops):
        raise Exception("Every op must be either create, add, remove or message")

    if any("added_key" not in op for op in parsed_ops if op["type"] == "add"):
        raise Exception("Every add operation must have an added_key")
    if any("removed_key" not in op for op in parsed_ops if op["type"] == "remove"):
        raise Exception("Every remove operation must have a removed_key")
    if any(
        "receptor_key" not in op or "message" not in op
        for op in parsed_ops
        if op["type"] == "message"
    ):
        raise Exception(
            "Every message operation must have a receptor_key and a message"
        )


def validate_hash_graph(ops_by_hash, parsed_ops):
    if any(len(op["preds"]) == 0 for op in parsed_ops if op["type"] != "create"):
        raise Exception("Every non-create op must have at least one predecessor")
    if any(
        pred not in ops_by_hash
        for op in parsed_ops
        if op["type"] != "create"
        for pred in op["preds"]
    ):
        raise Exception("Every hash must resolve to another op in the set")


def get_successors_per_op(ops_by_hash):
    successors = {}
    for hash, op in ops_by_hash.items():
        for pred in op.get("preds", []):
            successors[pred] = successors.get(pred, set()) | {hash}

    return successors


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


def get_creation_op(ops_by_hash):
    create_ops = [
        (hash, op) for hash, op in ops_by_hash.items() if op["type"] == "create"
    ]
    if len(create_ops) != 1:
        raise Exception("There must be exactly one create operation")

    return create_ops[0]


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

    for hash, op in ops_by_hash.items():
        # Check if op is valid
        is_op_valid(hash, ops_by_hash)

    return members
