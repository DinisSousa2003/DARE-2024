# Decentralised access control project

## Set-up

Set up a Python virtual environment in a new, empty directory:

```bash
brew install python # or equivalent on your OS
python3 -m venv venv
source venv/bin/activate # or venv/Scripts/activate
pip install -r requirements.txt
```

Then run it using `python acl_test_operations.py`. It should print out that it ran the tests, and "OK".

## How it works

The code uses the [Ed25519](https://en.wikipedia.org/wiki/EdDSA) algorithm from the [PyNaCl](https://pynacl.readthedocs.io/en/latest/signing/) package for digital signatures, the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) algorithm from the Python standard library as hash function, and the [unittest](https://docs.python.org/3/library/unittest.html) module from the Python standard library for test cases.

The `create_op()`, `add_op()`, and `remove_op()` functions generate signed operations to create a group, add a member to a group, and remove a member from a group respectively. These operations are organised into a hash graph as described in the lecture. See `TestAccessControlList.test_add_remove()` at the end of the file for an example of how to use these functions.

The `interpret_ops()` function takes a set of these access control operations and determines the set of public keys that are currently group members: that is, those keys that have been added, and not subsequently been removed again (the group creator is implicitly added). The function first checks all the signatures, and then checks that the hash graph is well-formed, raising an exception it if not.

The algorithm in `interpret_ops()` is currently a very simple one, in which only the group creator is allowed to add and remove group members. This avoids the problems discussed in the lecture, where two group members concurrently remove each other. But it's also a very restrictive model. Your task is to make the algorithm more flexible or powerful; how exactly you do this is left up to you.

## What to do

Some suggestions (you don't have to do these in order, and feel free to do other things if you want):

1. Explore the code and how it works by writing some more test cases. Include some tests of failure cases, e.g. an operation with an invalid signature, or an operation signed by an unauthorised key. You can use [`assertRaises()`](https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertRaises) to check that a test case raises an expected exception.
2. Integrate a notion of application messages into the algorithm. For example, you could make a chat room that only current members are allowed to post to. If a user is removed, any messages they posted while they were a member remain valid, but you should ignore any messages they post after they are removed or concurrently with their removal. You can do this by signing application messages and making them a part of the hash graph, just like access control operations.
3. Change the access control algorithm to use the Matrix approach instead of the currently implemented one. That is, every user has a power level, a user is allowed to add other users at a power level less than or equal to their own, and a user is allowed to remove other users with a power level strictly less than their own. The group creator starts with a fixed power level, e.g. 100. What should happen if the same user is added multiple times with different power levels?
4. Change the access control algorithm to use another conflict resolution approach, such as the seniority-based solution outlined in the lecture.
5. Instead of hand-writing test cases, you can also try property-based testing, which generates lots of random examples and checks that they produce the expected output. You could use the [Hypothesis library](https://hypothesis.readthedocs.io/en/latest/) for this.
6. Implement a form of permission delegation: for example, you could have one group that represents a team of collaborators, and another group that represents the access control or a particular document or chat room. Instead of giving individual users access to the document or room, you could delegate access to the team, so that any member of the team can access the document/room, and the team membership can be managed separately. With this, you could even have a "team" representing all the devices belonging to one particular user; then a user could authorise and revoke devices without having to update the permissions on every document they have access to.
7. A problem with the seniority-based access control algorithm is that a compromised key could be used long after it has been removed (even years later) to cause problems. Design an approach that would allow a removed key to become useless after some amount of time has elapsed.

Whatever you do, make sure that `interpret_ops()` always produces the same result regardless of the order in which it iterates over the set of operations. This is important to ensure convergence, i.e. that any two devices come to the same conclusion of who the group members are, regardless of the order in which they received the operations. Python randomises the iteration order of sets every time you start the Python process, so if you have a test that sometimes passes and sometimes fails, it could well be that you're accidentally relying on iteration order.