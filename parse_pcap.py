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


def parse_pcap(file: str = PCAP_FILE) -> tuple:
    """ Read the PCAP file and return timestamps and pcap data """

    buffer_list = []    # store a list of buffers
    ts_list = []        # store a list of timestamps
    try:
        with open(file, 'rb') as pcap_file:
            print(f"\n[*] Reading PCAP file - {file}\n")
            try:
                pcap = dpkt.pcap.Reader(pcap_file)
                for timestamp, buffer in pcap:
                    buffer_list.append(buffer)
                    ts_list.append(timestamp)
            except dpkt.NeedData:
                sys.stderr.write(f'\n[-] No data found in PCAP file: {file}\n\n')
                sys.exit()
            except dpkt.UnpackError:
                sys.stderr.write('\n[-] DPKT error occured while unpacking.\n\n')
                sys.exit()
            except dpkt.Error as err:
                err = err.__class__.__name__
                sys.stderr.write(f'\n[-] An error occured while reading PCAP file. {err}\n\n')
                sys.exit()
            print("[+] Successfully extracted data from PCAP file.\n")
    except FileNotFoundError:
        sys.stderr.write(f'\n[-] PCAP file: {file} - NOT Found!\n\n')
        sys.exit()
    except Exception as err:
        sys.stderr.write(f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n')
        sys.exit()

    return (ts_list, buffer_list)


def parse_ethernet(pcap_data: tuple) -> list:
    """ Read the PCAP file and return ethernet data in the form of a list """

    eth_list = []
    _, buffer = pcap_data
    for buf in buffer:
        try:
            eth_list.append(dpkt.ethernet.Ethernet(buf))
        except dpkt.Error as err:
            err = err.__class__.__name__
            sys.stderr.write('\n[-] An error occured while parsing data to Ethernet. {err}\n\n')
            sys.exit()
        except Exception as err:
            sys.stderr.write(f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n')
            sys.exit()
    print('[+] Successfully extracted Ethernet Data from PCAP file.\n')

    return eth_list


def tabulate_data(pcap_data: tuple) -> None:
    """ Extract necessary data and tabulate the network data
    """

    packet_type_dict: dict = {}
    timestamp, buffer = pcap_data
    print("[*] Tabulating the data from PCAP file.\n")
    for i, buf in enumerate(buffer):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            tmp = {'packets': 0,
                   'first_timestamp': '',
                   'last_timestamp': '',
                   'total_packet_length': 0,
                   'is_first': False}
            protocol_type = dpkt.ip.get_ip_proto_name(eth.data.p)
            packet_type_dict.setdefault(protocol_type, tmp)
            packet_type_dict[protocol_type]['packets'] += 1
            packet_type_dict[protocol_type]['total_packet_length'] += len(buf)

            utc_time = datetime.datetime.utcfromtimestamp(timestamp[i])
            if packet_type_dict[protocol_type]['is_first'] is False:
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
    for key, value in packet_type_dict.items():
        tmp_append([key,
                    value['packets'],
                    value['first_timestamp'],
                    value['last_timestamp'],
                    value['total_packet_length']/value['packets']])

    print(tabulate(tmp_list,
                   headers=['Packet Type',
                            'Number of Packets',
                            'First Timestamp (UTC)',
                            'Last Timestamp (UTC)',
                            'Mean Packet Length'],
                   tablefmt='pretty'))
    print("\n[+] Successfully tabulated the data in PCAP File.\n")


if __name__ == "__main__":
    tabulate_data(parse_pcap(PCAP_FILE))
