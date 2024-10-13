import unittest
from nacl.signing import SigningKey
from acl_helpers import hex_hash, verify_msg
from acl_operations import create_op, add_op, remove_op
from acl_validation import precedes, find_leaves, compute_seniority, authority_graph, find_cycles, get_member_nodes, compute_validity, compute_membership
from pprint import pprint


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

        self.assertEqual(precedes(ops_by_hash, hex_hash(create), hex_hash(add_b)), True)
        self.assertEqual(precedes(ops_by_hash, hex_hash(create), hex_hash(add_c)), True)

        self.assertEqual(precedes(ops_by_hash, hex_hash(add_b), hex_hash(rem_b)), True)
        self.assertEqual(precedes(ops_by_hash, hex_hash(add_c), hex_hash(rem_b)), True)
        self.assertEqual(precedes(ops_by_hash, hex_hash(create), hex_hash(rem_b)), True)

        self.assertEqual(precedes(ops_by_hash, hex_hash(rem_b), hex_hash(add_b)), False)
        self.assertEqual(precedes(ops_by_hash, hex_hash(rem_b), hex_hash(add_c)), False)
        self.assertEqual(precedes(ops_by_hash, hex_hash(rem_b), hex_hash(create)), False)

        self.assertEqual(precedes(ops_by_hash, hex_hash(add_b), hex_hash(create)), False)
        self.assertEqual(precedes(ops_by_hash, hex_hash(add_c), hex_hash(create)), False)


    def test_find_leaves(self):
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["alice"], self.public["carol"], [hex_hash(create)])
        add_d = add_op(self.private["alice"], self.public["dave"], [hex_hash(add_b)])
        rem_b = remove_op(
            self.private["alice"],
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c)],
        )

        ops = {create, add_b, add_c, add_d, rem_b}
        self.assertCountEqual(find_leaves(ops), [hex_hash(add_d), hex_hash(rem_b)])
        
    def test_compute_seniority(self):
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        add_c = add_op(self.private["alice"], self.public["carol"], [hex_hash(create)])
        add_d = add_op(self.private["alice"], self.public["dave"], [hex_hash(add_b)])
        rem_b = remove_op(
            self.private["alice"],
            self.public["bob"],
            [hex_hash(add_b), hex_hash(add_c)],
        )

        ops = {create, add_b, add_c, add_d, rem_b}
        #pprint(compute_seniority(ops))

    def test_authorityGraph(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        rem_b = remove_op(self.private["alice"], self.public["bob"], [hex_hash(add_b)])
        add_c = add_op(self.private["bob"], self.public["carol"], [hex_hash(add_b)])
        rem_a = remove_op(self.private["carol"], self.public["alice"], [hex_hash(add_c)])

        #Compute authority graph
        auth_graph = authority_graph({create, add_b, rem_b, add_c, rem_a})

        #Check if the authority graph is correct
        self.assertTrue((hex_hash(create), ("member", self.public["alice"])) in auth_graph)
        self.assertTrue((hex_hash(create), hex_hash(add_b)) in auth_graph)
        self.assertTrue((hex_hash(create), hex_hash(rem_b)) in auth_graph)
        self.assertTrue((hex_hash(add_b), ("member", self.public["bob"])) in auth_graph)
        self.assertTrue((hex_hash(add_b), hex_hash(add_c)) in auth_graph)
        self.assertTrue((hex_hash(add_c), ("member", self.public["carol"])) in auth_graph)
        self.assertTrue((hex_hash(add_c), hex_hash(rem_a)) in auth_graph)
        self.assertTrue((hex_hash(rem_a), ("member", self.public["alice"])) in auth_graph)
        self.assertTrue((hex_hash(rem_a), hex_hash(rem_b)) in auth_graph)
        self.assertTrue((hex_hash(rem_b), ("member", self.public["bob"])) in auth_graph)
        self.assertTrue((hex_hash(rem_b), hex_hash(add_c)) in auth_graph)
        
        self.assertTrue(len(auth_graph) == 11)

        members = get_member_nodes(auth_graph)

        self.assertTrue(len(members) == 3)
        
        cycles = find_cycles(auth_graph, members)

        self.assertEqual(len(cycles), 1)


    def test_cycles(self):

        auth_graph = {("create", ("member", "alice")),
                          ("create", "add_b"),
                          ("create", "rem_b"),
                          ("add_b", ("member", "bob")),
                          ("add_b", "add_c"),
                          ("add_c", ("member", "carol")),
                          ("add_c", "rem_a"),
                          ("rem_a", ("member", "alice")),
                          ("rem_a", "rem_b"),
                          ("rem_b", ("member", "bob")),
                          ("rem_b", "add_c"),
                          }

        #Check if the authority graph has cycles
        members = get_member_nodes(auth_graph)

        self.assertTrue(len(members) == 3)
        
        cycles = find_cycles(auth_graph, members)

        self.assertEqual(len(cycles), 1)

        self.assertCountEqual(cycles[0], ['add_c', 'rem_b', 'rem_a'])

    def test_validity(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        rem_b = remove_op(self.private["alice"], self.public["bob"], [hex_hash(add_b)])
        add_c = remove_op(self.private["bob"], self.public["carol"], [hex_hash(rem_b)])

        ops = {create, add_b, rem_b, add_c}

        #Compute authority graph
        auth_graph = authority_graph(ops)

        '''
        for n in auth_graph:
            print(n)

        print("###############")
        '''

        self.assertEqual(len(auth_graph), 8)
        
        ops_by_hash = {hex_hash(op): verify_msg(op) for op in ops}

        members = get_member_nodes(auth_graph)

        valid = set()

        for member in members:
            valid.union(compute_validity(ops_by_hash, auth_graph, member, valid))

        '''
        for v in valid:
            print(v)
        '''

        #The creation of the group, adding b and removing b should be valid, as well as member A
        self.assertEqual(len(valid), 4)

    def test_compute_membership(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        rem_b = remove_op(self.private["alice"], self.public["bob"], [hex_hash(add_b)])
        add_c = add_op(self.private["bob"], self.public["carol"], [hex_hash(add_b)])
        rem_a = remove_op(self.private["carol"], self.public["alice"], [hex_hash(add_c)])

        ops = {create, add_b, rem_b, add_c, rem_a}

        members = compute_membership(ops)

        self.assertIn(self.public["alice"], members)
        self.assertNotIn(self.public["bob"], members)
        self.assertNotIn(self.public["carol"], members)

if __name__ == "__main__":
    unittest.main()
