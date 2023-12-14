The forwarding table will be generated as follows:
```
[
    [(Destination IP1, Destination Port1), (Next hop IP1, Next hop PORT1), COST],
    [(Destination IP2, Destination Port2), (Next hop IP2, Next hop PORT2), COST],
    [(Destination IP3, Destination Port3), (Next hop IP3, Next hop PORT3), COST],
]
```

The cost -> if `None` for a destination, means there is no path to the destination (yet)  
* The next hop IP and Port -> If `None`, means no path exist for that destination.
* For neighbours, we are *NOT* removing the next hop entry, but just setting the cost to `None`

Both the files require the utils.py to be in the same directory as the code file. Kindly include the utils.py for the same.

Extra credits: We have included the sender and requester (with the appropriate changes) for the extra credits.