"""
Script: parse_pcap.py
Description: Extract data from PCAP file and tabulate the
            data according to packet types
Author: Thar Htet Nyan
Date: July 2022
"""


import sys
import datetime
import dpkt
from tabulate import tabulate


PCAP_FILE = "evidence-packet-analysis.pcap"
# PCAP_FILE = "../Week 3/week7code/filtered4.pcap"
# PCAP_FILE = "../Week 3/week7files/filtered2.pcap"
# PCAP_FILE = "../Week 3/week7files/filtered3.pcap"
# PCAP_FILE = "../pcap_file.pcap"


def parse_pcap(file: str = PCAP_FILE) -> list:
    """ Read the PCAP file and return timestamps and pcap data """

    pcap_data = [] # store buffer and timestamp
    try:
        with open(file, 'rb') as pcap_file:
            print(f"\n[*] Reading PCAP file - {file}\n")
            try:
                pcap = dpkt.pcap.Reader(pcap_file)
                for timestamp, buffer in pcap:
                    pcap_data.append((timestamp, buffer))
            except dpkt.NeedData:
                sys.stderr.write(f'\n[-] No data found in PCAP file: {file}\n\n')
                sys.exit()
            except dpkt.UnpackError:
                sys.stderr.write('\n[-] DPKT error occured while unpacking.\n\n')
                sys.exit()
            except dpkt.Error as err:
                dpkt_err = err.__class__.__name__
                sys.stderr.write(f'\n[-] An error occured while reading PCAP file. {dpkt_err}\n\n')
                sys.exit()
            print("[+] Successfully extracted data from PCAP file.\n")
    except FileNotFoundError:
        sys.stderr.write(f'\n[-] PCAP file: {file} - NOT Found!\n\n')
        sys.exit()
    except Exception as err:
        base_err_class = err.__class__
        base_err_name = err.__class__.__name__
        sys.stderr.write(f'\n[-] {base_err_class}: {base_err_name}\n\n')
        sys.exit()

    return pcap_data


def parse_inet_proto(pcap_data: list) -> list:
    """ Read the PCAP file and return internet protocol data in the form of a list """

    inet_proto_list = []
    for _, buffer in pcap_data:
        try:
            inet_proto_list.append(dpkt.ethernet.Ethernet(buffer).data)
        except dpkt.Error as err:
            msg = 'An error occured while parsing data to Internet protocol.'
            err = f'{msg} {err.__class__.__name__}'
            sys.stderr.write('\n[-] {err}\n\n')
            sys.exit()
        except Exception as err:
            sys.stderr.write(f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n')
            sys.exit()
    print('[+] Successfully extracted Internet Protocol Data from PCAP file.\n')

    return inet_proto_list


def tabulate_data(pcap_data: list) -> None:
    """ Extract necessary data and tabulate the network data
    """

    packet_type_dict: dict = {}
    print("[*] Tabulating the data from PCAP file.\n")
    for timestamp, buffer in pcap_data:
        try:
            inet_proto = dpkt.ethernet.Ethernet(buffer).data
            tmp = {'packets': 0,
                   'total_packet_length': 0,
                   'first_timestamp': '',
                   'last_timestamp': '',
                   'is_first': False}
            protocol_type = dpkt.ip.get_ip_proto_name(inet_proto.p)
            packet_type_dict.setdefault(protocol_type, tmp)
            packet_type_dict[protocol_type]['packets'] += 1
            packet_type_dict[protocol_type]['total_packet_length'] += len(buffer)

            utc_time = datetime.datetime.utcfromtimestamp(timestamp)
            if not packet_type_dict[protocol_type]['is_first']:
                packet_type_dict[protocol_type]['first_timestamp'] = utc_time
                packet_type_dict[protocol_type]['is_first'] = True

            packet_type_dict[protocol_type]['last_timestamp'] = utc_time

        except dpkt.Error as err:
            err = err.__class__.__name__
            sys.stderr.write('\n[-] An error occured while parsing data to Ethernet. {err}\n\n')
            sys.exit()
        except AttributeError:
            sys.stderr.write('\n[-] Attribute Error occured.\n\n')
            sys.exit()
        except Exception as err:
            sys.stderr.write(f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n')
            sys.exit()

    tmp_list: list = []
    tmp_append = tmp_list.append
    for packet_type, info in packet_type_dict.items():
        tmp_append([packet_type,
                    info['packets'],
                    info['first_timestamp'],
                    info['last_timestamp'],
                    info['total_packet_length']/info['packets']])

    print(tabulate(tmp_list,
                   headers=['Packet Types',
                            'Number of Packets',
                            'First Timestamp (UTC)',
                            'Last Timestamp (UTC)',
                            'Mean Packet Length'],
                   tablefmt='pretty'))
    print("\n[+] Successfully tabulated the data in PCAP File.\n")


if __name__ == "__main__":
    tabulate_data(parse_pcap(PCAP_FILE))
