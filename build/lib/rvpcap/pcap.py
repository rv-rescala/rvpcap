import dpkt
import socket

class PCAPModel:
    pcap = None

    def __init__(self, input):
        self.pcap = dpkt.pcap.Reader(open(input,'rb'))

    @classmethod
    def ts_analyze(cls, input, target_dst_address, ts_out = None, pcap_out = None, target_time = None):
        if ts_out:
            f_ts_out = open(ts_out,'w+b')
        if pcap_out:
            f_pcap_out = dpkt.pcap.Writer(open(pcap_out,'wb'))
        # counters
        packet_count = 0
        p_seq = 0
        is_first = True
        start_time = 0

        for timestamp,buf in pcap:
            if target_time:
                if timestamp < float(target_time[0]):
                    continue
                elif timestamp > float(target_time[1]):
                    print("clip end")
                    return
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) == dpkt.ip.IP:
                ip = eth.data
                if socket.inet_ntoa(ip.dst) == target_dst_address:
                    tcp  = ip.data
                    rtp = rtp_pkt=dpkt.rtp.RTP(tcp.data)
                    rtp_container = rtp.data
                    seq = int(rtp.seq)
                    sub_seq = seq - p_seq
                    # seqの確認
                    if not((sub_seq == 1) or (sub_seq == -65535)):
                        if is_first:
                            start_time = timestamp
                            is_first = False
                        else:
                            print(f"rtp seq error,{str(datetime.datetime.fromtimestamp(timestamp))},{seq},{p_seq}")
                    # rtpコンテナの取得
                    for mpeg2_ts in [rtp_container[i: i+188] for i in range(0, len(rtp_container), 188)]:
                        MPEG2TSModel.parse(timestamp, mpeg2_ts)
                    if ts_out:
                        f_ts_out.write(rtp_container)
                    if pcap_out:
                        f_pcap_out.writepkt(eth,timestamp)
                    p_seq = seq
        f_ts_out.close()
        f_pcap_out.close()
