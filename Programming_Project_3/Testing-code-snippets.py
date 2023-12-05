
# TESTING
    """
    # print("\n".join(str(fwd_entry) for fwd_entry in fwd_table))
    link_state_vector = []
    lsv = "10.141.147.221:5000:1|10.141.147.221:6000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)

    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 7000]))
    print_fwd_table(fwd_table)

    print("\n\n\n\nSimulate the case that an indirect node is gone\n")
    link_state_vector = []
    lsv = "10.141.147.221:6000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)
    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 7000]))
    print_fwd_table(fwd_table)

    print("\n\n\n\nSimulate the case that the gone indirect node can be reached through other\n")
    link_state_vector = []
    lsv = "10.141.147.221:5000:1|10.141.147.221:7000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)
    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 6000]))
    print_fwd_table(fwd_table)
    """
