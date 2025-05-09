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
from io import TextIOWrapper
from typing import OrderedDict
from tabulate import tabulate
import parse_pcap as p_pcap
import tlogger as tlog



EMAIL_OUTPUT_FILE = os.path.join(p_pcap.OUTPUT_FOLDER, 'email_output_table.txt')
IMAGE_REQUEST_FILE = os.path.join(p_pcap.OUTPUT_FOLDER, 'image_request_table.txt')
TRAFFIC_FILE = os.path.join(p_pcap.OUTPUT_FOLDER, 'ip_traffic_table.txt')


TO_EMAIL_REGEX = re.compile(r'To:\s.*\s*<([\w._%-]+@[\w]+\.[\w]+?)>')
FROM_EMAIL_REGEX = re.compile(r'From:\s.*\s*<([\w._%-]+@[\w]+\.[\w]+?)>')

URL_REGEX = re.compile(r'GET\s([\w/_%+-]+\.(jpg|png|gif|jpeg))[\s|?|]', re.I)
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


def extract_traffics(inet_proto_list: list, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> dict:
    """ Extract source and destination IP addresses and count traffics.
    Use number of traffics as keys and list the traffics with same traffic counts as values.
    Return them as a dictionary
    """

    traffics_dict: dict = {}
    log = "[*] Extracting traffics data.\n"
    tlog.logger(log, out_file)
    for inet_proto in inet_proto_list:
        src = socket.inet_ntoa(inet_proto.src)
        dst = socket.inet_ntoa(inet_proto.dst)
        tmp_key = (src, dst)
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

    log = "[+] Successfully extracted traffics data.\n"
    tlog.logger(log, out_file)

    return traffics_dict


def analyse_packets(inet_proto_list: list, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> tuple:
    """ Make a unique list of extracted TO email addresses, FROM email addresses,
    full URLs for image requests, image filenames.
    Return them as a tuple
    """

    to_email_list = []
    from_email_list = []
    full_url_list = []
    filename_list = []

    log = "[*] Extracting TO, FROM email addresses, full image URLs and image names.\n"
    tlog.logger(log, out_file)
    for inet_proto in inet_proto_list:
        decoded_data = inet_proto.data.data.decode('latin-1')
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

    log = "[+] Successfully extracted TO, FROM email addresses, full image URLs and image names.\n"
    tlog.logger(log, out_file)

    return (set(to_email_list), set(from_email_list), full_url_list, filename_list)


def display_analysed_data(inet_proto_list: list, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> None:
    """ Extract necessary data for analysis and display the analysis results in tables
    """

    data_dict1 = {}
    data_dict2 = {}

    (data_dict1['To Email Addresses'], data_dict1['From Email Addresses'], data_dict2['Full URLs'],
    data_dict2['Image Filenames']) = analyse_packets(inet_proto_list)

    traffics_dict = extract_traffics(inet_proto_list)

    log = "[*] Tabulating TO and FROM email addresses.\n"
    tlog.logger(log, out_file)
    email_tabulated_data = tabulate(data_dict1, headers='keys', tablefmt='psql')
    tlog.logger(email_tabulated_data+"\n\n", out_file)
    log = "[+] Successfully tabulated TO and FROM email addresses.\n"
    tlog.logger(log, out_file)

    log = f"[*] Writing email outputs to - {EMAIL_OUTPUT_FILE}.\n"
    tlog.logger(log, out_file)
    with open(EMAIL_OUTPUT_FILE, 'wb') as file:
        file.write(email_tabulated_data.encode('utf-8'))

    log = f"[+] Successfully written email ouputs to - {EMAIL_OUTPUT_FILE}.\n"
    tlog.logger(log, out_file)

    log = "[*] Tabulating Full URLs and Image filenames.\n"
    tlog.logger(log, out_file)
    image_req_tabulated_data = tabulate(data_dict2, headers='keys', tablefmt='grid')
    tlog.logger(image_req_tabulated_data+"\n\n", out_file)
    log = "[+] Successfully tabulated Full URLs and Image filenames.\n"
    tlog.logger(log, out_file)

    log = f"[*] Writing image requests to - {IMAGE_REQUEST_FILE}.\n"
    tlog.logger(log, out_file)
    with open(IMAGE_REQUEST_FILE, 'wb') as file:
        file.write(image_req_tabulated_data.encode('utf-8'))

    log = f"[+] Successfully written image requests to - {IMAGE_REQUEST_FILE}.\n"
    tlog.logger(log, out_file)

    log = "[*] Tabulating Traffics and Number of Traffics.\n"
    tlog.logger(log, out_file)
    traffic_table = [[f'{src} -> {dst}', traffic_count]
                       for traffic_count, traffic in traffics_dict.items()
                       for src, dst in traffic]

    traffic_tabulated_data = tabulate(traffic_table,
                                      headers=['Traffic',
                                               'Number of Traffics'],
                                      tablefmt='psql')
    tlog.logger(traffic_tabulated_data+"\n\n", out_file)
    log = "[+] Successfully tabulated Traffics and Number of traffics.\n"
    tlog.logger(log, out_file)

    log = f"[*] Writing traffic data to - {TRAFFIC_FILE}.\n"
    tlog.logger(log, out_file)
    with open(TRAFFIC_FILE, 'wb') as file:
        file.write(traffic_tabulated_data.encode('utf-8'))

    log = f"[+] Successfully written traffic data to - {TRAFFIC_FILE}.\n"
    tlog.logger(log, out_file)

    # with open('ip_traffic_table1.txt', 'w') as f:
    #     f.write(tabulate([[k, v] for k, v in traffics],
    #                       headers=['Traffic',
    #                               'Number of traffics'],
    #                       tablefmt='psql'))


if __name__ == "__main__":
    display_analysed_data(p_pcap.parse_inet_proto(p_pcap.parse_pcap()))
    p_pcap.OUT_FILE.close()
