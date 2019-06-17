from dataclasses import dataclass
from typing import List
import datetime
import dpkt

@dataclass(frozen=True)
class RTP:
    seq: int
    container: bytes

class RTPModel:
    prev_rtp:RTP = None

    def check_seq_number(self, dst_address, timestamp, rtp: RTP):
        if not self.prev_rtp:
            prev_rtp = rtp
        else:
            sub_seq = rtp.seq - self.prev_rtp.seq
            if not((sub_seq == 1) or (sub_seq == -65535)):
                if self.is_first:
                    start_time = timestamp
                    is_first = False
                else:
                    print(f"rtp seq error,{dst_address},{str(datetime.datetime.fromtimestamp(timestamp))},{rtp.seq},{self.prev_rtp.seq}")

    @staticmethod
    def parse(tcp):
        rtp = dpkt.rtp.RTP(tcp.data)
        rtp_container = rtp.data
        seq = int(rtp.seq)
        return RTP(seq, rtp_container)

