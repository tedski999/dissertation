import dpkt
import statistics

for file in ['ech_disabled.pcap', 'ech_centralised.pcap', 'ech_distributed.pcap']:
    flows = {}
    times = []
    count = 0

    with open(file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            count += 1

            flow_id = (ip.src, ip.dst, tcp.sport, tcp.dport)
            flow = flows.get(flow_id)
            if flow is None:
                if not tcp.flags & dpkt.tcp.TH_SYN:
                    continue
                flow = timestamp

            if tcp.flags & dpkt.tcp.TH_FIN:
                t = timestamp - flow
                times.append(t * 1000)
                del flows[flow_id]
            else:
                flows[flow_id] = flow

    print(file)
    print(len(times), count)
    print("Max", max(times))
    print("Min", min(times))
    print("Avg", statistics.mean(times))
    print("Dev", statistics.stdev(times))
    print()
