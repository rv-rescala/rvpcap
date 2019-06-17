from dataclasses import dataclass
from typing import List
import datetime

@dataclass(frozen=True)
class MPEG2TS:
    """[summary]
    https://wikiwiki.jp/redstrange/MPEG-2%20TS
    """
    sync_byte: hex # 8bit
    payload_unit_start_indicator: int # 1bit
    transport_priority: int # 1bit
    pid: int # 13bit
    transport_scrambling_control: int # 2bit
    adaptation_field_control: int # 2bit
    continuity_counter: int # 4bit

class MPEG2TSModel:
    cc_by_pid = dict()

    def print_pids():
        """[summary]
        8191 => 常に0
        6105 => 映像?
        2105 => 音声?
        5105 => SI?
        """
        for k in MPEG2TSModel.cc_by_pid.keys():
            print(k)
        print("---")


    @classmethod
    def parse(cls, timestamp, mpeg2_ts):
        ts_bytearray = bytearray(mpeg2_ts)
        r = MPEG2TS(
        sync_byte= hex(ts_bytearray[0]),
        payload_unit_start_indicator = ts_bytearray[1] & 0x80,
        transport_priority = ts_bytearray[1] & 0x10,
        pid = int.from_bytes(bytearray([ts_bytearray[1] & 0x1f, ts_bytearray[2]]), byteorder='big'),
        transport_scrambling_control = ts_bytearray[3] & 0xC0,
        adaptation_field_control = ts_bytearray[3] & 0x30,
        continuity_counter = ts_bytearray[3] & 0x0f)
        if r.pid != 0: # PID0はスキップ
            if r.pid in MPEG2TSModel.cc_by_pid:
                prev_cc = MPEG2TSModel.cc_by_pid[r.pid].continuity_counter
                current_cc = r.continuity_counter
                sub_cc = current_cc - prev_cc
                if not(sub_cc == 1 or sub_cc == -15 or sub_cc == 0):
                    print(f"cc error,{str(datetime.datetime.fromtimestamp(timestamp))},{r.pid},{prev_cc},{current_cc}")
                MPEG2TSModel.cc_by_pid[r.pid] = r
            else:
                MPEG2TSModel.cc_by_pid.update([(r.pid, r)])
        return r
