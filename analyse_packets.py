"""
Script: analyse_packets.py
Description: Extract TO and FROM email addresses Full URLs, Image filenames
            and traffics from PCAP file. Display all the extracted data
Author: Thar Htet Nyan
Date: July 2022
"""


import re
import os
import socket
from typing import OrderedDict
from tabulate import tabulate
import parse_pcap as p_pcap


TRAFFIC_FILE = 'ip_traffic_table.txt'

TO_EMAIL_REGEX = re.compile(r'To:\s.*\s*<([\w._%-]+@[\w]+\.[\w]+?)>')
FROM_EMAIL_REGEX = re.compile(r'From:\s.*\s*<([\w._%-]+@[\w]+\.[\w]+?)>')

URL_REGEX = re.compile(r'GET\s([\w/_%+-]+\.(jpg|png|gif|jpeg))\s', re.I)
HOST_REGEX = re.compile(r'Host:\s([\w]+\.[\w_+-]+\.[\w]+\.*[\w]*)')


def extract_email_addresses(data: str) -> tuple:
    """ Extract TO email address and FROM email address from string using Regex.
    Return them as a tuple
    """

    to_email = TO_EMAIL_REGEX.findall(data)
    from_email = FROM_EMAIL_REGEX.findall(data)

    return (to_email, from_email)


def extract_files(data: str) -> tuple:
    """ Extract full URL for image requests, image filename from string using Regex.
    Return them as a tuple
    """

    full_url = ""
    filename = ""

    host = HOST_REGEX.findall(data)
    url = URL_REGEX.findall(data)

    if host and url:
        full_url = "http://"+host[0] + url[0][0]
        filename = os.path.split(full_url)[1]

    return (full_url, filename)


def extract_traffics(eth_list: list) -> dict:
    """ Extract source and destination IP addresses and count traffics.
    Use number of traffics as keys and list the traffics with same traffic counts as values.
    Return them as a dictionary
    """

    traffics_dict: dict = {}
    print("[*] Extracting traffics data.\n")
    for eth in eth_list:
        src = socket.inet_ntoa(eth.data.src)
        dst = socket.inet_ntoa(eth.data.dst)
        tmp_key = src + ' -> ' + dst
        if tmp_key in traffics_dict:
            traffics_dict[tmp_key] += 1
        else:
            traffics_dict.setdefault(tmp_key, 1)

    # sorting the traffics_dict according to number of traffic
    tmp_dict: dict = {}
    for key, value in traffics_dict.items():
        tmp_dict.setdefault(value, []).append(key)

    traffics_dict = OrderedDict(sorted(tmp_dict.items(), reverse=True))
    # sorting ends here

    # alternative sorting method
    # traffics_dict = sorted(traffics_dict.items(),
    #                       key=lambda t: t[1],
    #                       reverse=True)

    print("[+] Successfully extracted traffics data.\n")

    return traffics_dict


def analyse_packets(eth_list: list) -> tuple:
    """ Make a unique list of extracted TO email addresses, FROM email addresses,
    full URLs for image requests, image filenames.
    Return them as a tuple
    """

    to_email_list = []
    from_email_list = []
    full_url_list = []
    filename_list = []

    print("[*] Extracting TO, FROM email addresses, full image URLs and image names.\n")
    for eth in eth_list:
        decoded_data = eth.data.data.data.decode('latin-1')
        to_email, from_email = extract_email_addresses(decoded_data)
        full_url, filename = extract_files(decoded_data)

        if to_email:
            to_email_list.append(to_email[0])
        if from_email:
            from_email_list.append(from_email[0])
        if full_url:
            full_url_list.append(full_url)
        if filename:
            filename_list.append(filename)

    print("[+] Successfully extracted TO, FROM email addresses, full image URLs and image names.\n")

    return (set(to_email_list), set(from_email_list), full_url_list, filename_list)


def display_analysed_data(eth_list: list) -> None:
    """ Extract necessary data for analysis and display the analysis results in tables
    """

    data_dict1 = {}
    data_dict2 = {}

    (data_dict1['To Email Addresses'], data_dict1['From Email Addresses'], data_dict2['Full URLs'],
    data_dict2['Image filenames']) = analyse_packets(eth_list)

    traffics_dict = extract_traffics(eth_list)

    print("[*] Tabulating TO and FROM email addresses.\n")
    print(tabulate(data_dict1, headers='keys', tablefmt='psql'), end="\n\n")
    print("[+] Successfully tabulated TO and FROM email addresses.\n")

    print("[*] Tabulating Full URLs and Image filenames.\n")
    print(tabulate(data_dict2, headers='keys', tablefmt='grid'), end="\n\n")
    print("[+] Successfully tabulated Full URLs and Image filenames.\n")

    print(f"[*] Writing traffic data to {TRAFFIC_FILE}.\n")
    with open(TRAFFIC_FILE, 'wb') as file:
        tabulated_data = tabulate([[i, k] for k, v in traffics_dict.items() for i in v],
                                    headers=['Traffic',
                                            'Number of traffics'],
                                    tablefmt='psql')
        file.write(tabulated_data.encode('utf-8'))

    print(f"[+] Successfully written traffic data to {TRAFFIC_FILE}.\n")

    # with open('ip_traffic_table1.txt', 'w') as f:
    #     f.write(tabulate([[k, v] for k, v in traffics],
    #                       headers=['Traffic',
    #                               'Number of traffics'],
    #                       tablefmt='psql'))


if __name__ == "__main__":
    display_analysed_data(p_pcap.parse_ethernet(p_pcap.parse_pcap(p_pcap.PCAP_FILE)))
