import sys
import datetime
import configparser
import argparse
from rvpcap.pcap import PCAPModel 

if __name__ == '__main__':
    # args
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', nargs='*', choices=['ts'], help="execute  functions")
    parser.add_argument('-ip', '--input_pcap', help="input pcap")
    parser.add_argument('-op', '--output_pcap', help="output pcap")
    parser.add_argument('-ot', '--output_ts', help="output ts")
    parser.add_argument('-ds', '--dst_address', help="target destination address")
    parser.add_argument('-tt', '--target_time', help="target timestamp[start,stop]", nargs='*')
    args = parser.parse_args()
    print(args)

    pcap = PCAPModel(input = args.input_pcap)

    if args.mode == "ts":
        pcap.ts_analyze(target_dst_address = args.dst_address, ts_out = args.output_ts, pcap_out=args.output_pcap, target_time=args.target_time)
