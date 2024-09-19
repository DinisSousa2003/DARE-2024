import unittest
from nacl.signing import SigningKey
from acl_helpers import hex_hash, verify_msg
from acl_operations import create_op, add_op, remove_op
from acl_validation import interpret_ops, precedes


class TestAccessControlList(unittest.TestCase):
    # Generate keys for all the participants
    private = {
        name: SigningKey.generate() for name in {"alice", "bob", "carol", "dave"}
    }
    public = {
        name: key.verify_key.encode().hex() for name, key in private.items()
    }  # name: public key
    friendly_name = {
        public_key: name for name, public_key in public.items()
    }  # public key: name

    def test_add_remove(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["alice"], self.public["carol"], [hex_hash(create)])
        rem_b = remove_op(
            self.private["alice"],
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c)],
        )

        # Compute group membership
        members = interpret_ops({create, add_b, add_c, rem_b})
        self.assertEqual(
            {self.friendly_name[member] for member in members}, {"alice", "carol"}
        )

    def test_bad_signature(self):
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["bob"], self.public["carol"], [hex_hash(create)])

        # A removes B with a false signature
        rem_b = remove_op(
            SigningKey.generate(),
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c)],
        )

        with self.assertRaises(Exception):
            interpret_ops({create, add_b, add_c, rem_b})
            # This should raise an exception

    def test_bad_hash(self):
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["alice"], self.public["carol"], [hex_hash(create)])

        # A removes B with a false hash
        rem_b = remove_op(
            self.private["alice"],
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c) + "00"],
        )

        with self.assertRaises(Exception):
            # This should raise an exception
            interpret_ops({create, add_b, add_c, rem_b})

    def test_precedence(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["alice"], self.public["carol"], [hex_hash(create)])
        rem_b = remove_op(
            self.private["alice"],
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c)],
        )

        ops = {create, add_b, add_c, rem_b}
        ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}

        self.assertEqual(precedes(ops_by_hash, create, verify_msg(add_b)), True)
        self.assertEqual(precedes(ops_by_hash, create, verify_msg(add_c)), True)

        self.assertEqual(precedes(ops_by_hash, add_b, verify_msg(rem_b)), True)
        self.assertEqual(precedes(ops_by_hash, add_c, verify_msg(rem_b)), True)
        self.assertEqual(precedes(ops_by_hash, create, verify_msg(rem_b)), True)

        self.assertEqual(precedes(ops_by_hash, rem_b, verify_msg(add_b)), False)
        self.assertEqual(precedes(ops_by_hash, rem_b, verify_msg(add_c)), False)
        self.assertEqual(precedes(ops_by_hash, rem_b, verify_msg(create)), False)

        self.assertEqual(precedes(ops_by_hash, add_b, verify_msg(create)), False)
        self.assertEqual(precedes(ops_by_hash, add_c, verify_msg(create)), False)


if __name__ == "__main__":
    unittest.main()
