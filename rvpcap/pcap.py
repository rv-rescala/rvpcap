import dpkt
import socket
import datetime
from rvpcap.mpeg2_ts import MPEG2TSModel
from rvpcap.rtp import RTPModel

class PCAPModel:
    pcap = None

    def __init__(self, input):
        self.pcap = dpkt.pcap.Reader(open(input,'rb'))

    def ts_analyze(self, dst_addresses, output_dir=None, is_pcap_output=False):
        # dict
        mpeg2_ts_models = dict(map(lambda da: (da, MPEG2TSModel()), dst_addresses))
        rtp_models = dict(map(lambda da: (da, RTPModel()), dst_addresses))
        if output_dir:
            output_csvs = dict(map(lambda da: (da, open(f"{output_dir}/{da}.csv","w")), dst_addresses))
            if is_pcap_output:
                output_pcaps = dict(map(lambda da: (da, dpkt.pcap.Writer(open(f"{output_dir}/{da}.pcap","wb"))), dst_addresses))

        for timestamp,buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) == dpkt.ip.IP:
                ip = eth.data
                dst_address = socket.inet_ntoa(ip.dst)
                mpeg2_ts_model = mpeg2_ts_models.get(dst_address)
                rtp_model = rtp_models.get(dst_address)
                if mpeg2_ts_model:
                    rtp = RTPModel.parse(ip.data)
                    rtp_model.check_seq_number(timestamp, dst_address, rtp)
                    mpeg2_ts_model.check_cc(timestamp, dst_address, rtp.container)
                    if output_dir:
                        output_csvs.get(dst_address).write(f"{timestamp},{rtp.seq}\n")
                    if is_pcap_output:
                        output_pcaps.get(dst_address).writepkt(eth, timestamp)

        map(lambda ot: ot.close(), output_csvs)
        map(lambda ot: ot.close(), output_pcaps)