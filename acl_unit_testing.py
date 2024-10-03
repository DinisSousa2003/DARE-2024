
import unittest
from nacl.signing import SigningKey
from acl_validation import authorityGraph, findCycles, getMemberNodes
from acl_helpers import hex_hash, verify_msg
from acl_operations import create_op, add_op, remove_op

#Build example from figure 6
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

    def test_authorityGraph(self):
        # Make some example ops
        create = create_op(self.private["alice"])
        add_b = add_op(self.private["alice"], self.public["bob"], [hex_hash(create)])
        rem_b = remove_op(self.private["alice"], self.public["bob"], [hex_hash(add_b)])
        add_c = add_op(self.private["bob"], self.public["carol"], [hex_hash(add_b)])
        rem_a = remove_op(self.private["carol"], self.public["alice"], [hex_hash(add_c)])

        #Compute authority graph
        authGraph = authorityGraph({create, add_b, rem_b, add_c, rem_a})

        #Check if the authority graph is correct
        self.assertTrue((hex_hash(create), ("member", self.public["alice"])) in authGraph)
        self.assertTrue((hex_hash(create), hex_hash(add_b)) in authGraph)
        self.assertTrue((hex_hash(create), hex_hash(rem_b)) in authGraph)
        self.assertTrue((hex_hash(add_b), ("member", self.public["bob"])) in authGraph)
        self.assertTrue((hex_hash(add_b), hex_hash(add_c)) in authGraph)
        self.assertTrue((hex_hash(add_c), ("member", self.public["carol"])) in authGraph)
        self.assertTrue((hex_hash(add_c), hex_hash(rem_a)) in authGraph)
        self.assertTrue((hex_hash(rem_a), ("member", self.public["alice"])) in authGraph)
        self.assertTrue((hex_hash(rem_a), hex_hash(rem_b)) in authGraph)
        self.assertTrue((hex_hash(rem_b), ("member", self.public["bob"])) in authGraph)
        self.assertTrue((hex_hash(rem_b), hex_hash(add_c)) in authGraph)
        
        self.assertTrue(len(authGraph) == 11)


    def test_cycles(self):

        authGraph = {("create", ("member", "alice")),
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
        members = getMemberNodes(authGraph)

        self.assertTrue(len(members) == 3)
        
        cycles = []
        for member in members:
            cycle = findCycles(authGraph, member, [])
            cycles.append(cycle)
            if member[1] == "alice":
                #self.assertTrue(len(cycle) == 3)
                print("alice", cycle, len(cycle))
            elif member[1] == "bob":                
                #self.assertTrue(len(cycle) == 3)
                print("bob", cycle, len(cycle))
            elif member[1] == "carol":
                #self.assertTrue(len(cycle) == 3)
                print("carol", cycle, len(cycle))

    def test_cycles2(self):

        authGraph = {("create", "add_b"),
                     ("add_b", "rem_c"),
                          ("rem_c", "create"),
                          }
        
        cycle = findCycles(authGraph, "create", [])
        print("testcycle2", cycle, len(cycle))
            

        

            
    

if __name__ == "__main__":
    unittest.main()
