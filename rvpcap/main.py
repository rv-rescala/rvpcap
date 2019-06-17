import sys
import datetime
import configparser
import argparse
from rvpcap.pcap import PCAPModel 

if __name__ == '__main__':
    # args
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', nargs='*', choices=['ts_analyze'], help="execute  functions", required=True)
    parser.add_argument('-ip', '--input_pcap', help="input pcap", required=True)
    parser.add_argument('-dst', '--dst_addresses', help="target destination address", nargs='*')
    parser.add_argument('-tt', '--target_time', help="target timestamp[start,stop]", nargs='*')
    parser.add_argument('-ot', '--output_ts', help="is output ts file", action="store_true")
    parser.add_argument('-op', '--output_pcap', help="is output pcap file", action="store_true")
    parser.add_argument('-od', '--output_dir', help="output dir")
    args = parser.parse_args()
    print(args)

    pcap = PCAPModel(input = args.input_pcap)

    if args.mode[0] == 'ts_analyze':
        print("ts_analyze mode")
        pcap.ts_analyze(dst_addresses = args.dst_addresses, output_dir=args.output_dir, is_pcap_output=args.output_pcap)
