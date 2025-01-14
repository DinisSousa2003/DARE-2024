import secrets
from acl_helpers import sign_msg

# Constants
PERMITTED_OPERATORS = {"create", "add", "remove"}


def create_op(signing_key):
    """Returns a group creation operation signed by ``signing_key``."""
    return sign_msg(signing_key, {"type": "create", "nonce": secrets.token_hex(16)})


def add_op(signing_key, added_key, deps):
    """Returns an operation signed by ``signing_key``, which adds ``added_key`` to the group.
    ``deps`` is a list of hashes of immediate predecessor operations."""
    return sign_msg(
        signing_key, {"type": "add", "added_key": added_key, "deps": deps}
    )


def remove_op(signing_key, removed_key, deps):
    """Returns an operation signed by ``signing_key``, which removes ``removed_key`` from the group.
    ``deps`` is a list of hashes of immediate predecessor operations."""
    return sign_msg(
        signing_key, {"type": "remove", "removed_key": removed_key, "deps": deps}
    )