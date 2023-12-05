The forwarding table will be generated as follows:
[
    [(Destination IP1, Destination Port1), (Next hop IP1, Next hop PORT1), COST, VALID],
    [(Destination IP2, Destination Port2), (Next hop IP2, Next hop PORT2), COST, VALID],
    [(Destination IP3, Destination Port3), (Next hop IP3, Next hop PORT3), COST, VALID],
]

The cost - if None, means there is no path to it (yet)
For neighbours, we will not remove the next hop entry, but just set the cost to None

In LSV, if the cost is None, that means that particular node is not reachable from the adjacent node