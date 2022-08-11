"""
Script: graph_analysis.py
Description: Extract data from PCAP file and draw a line chart of
            number of packets between each time intervals
Author: Thar Htet Nyan
Date: August 2022
"""


import statistics as stats
from datetime import datetime
from io import TextIOWrapper
import matplotlib.pyplot as plt
import matplotlib.dates as mdt
import parse_pcap as p_pcap
import tlogger as tlog


INTERVAL = 5


def extract_data(pcap_data: list, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> dict:
    """ Extract time intervals and packet counts between each time interval.
        Return dictionary of time_intervals(key) and packet counts(value)
    """

    start_time = pcap_data[0][0]
    data: dict = {}

    log = "[*] Extracting data to create a line chart.\n"
    tlog.logger(log, out_file)
    for timestamp, _ in pcap_data:
        if timestamp > start_time + INTERVAL:
            start_time += INTERVAL

        if start_time in data:
            data[start_time] += 1
        else:
            data.setdefault(start_time, 1)
    log = "[+] Successfully extracted data to create a line chart.\n"
    tlog.logger(log, out_file)

    return data


def draw_graph(extracted_data: dict, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> None:
    """ Draw a line chart from extracted data
    """

    log = "[*] Drawing a line chart.\n"
    tlog.logger(log, out_file)
    try:
        x_values = list(extracted_data)
        y_values = list(extracted_data.values())
        x_dates = [datetime.utcfromtimestamp(i) for i in x_values]

        plt.plot(x_dates, y_values)
        plt.format_xdata = mdt.DateFormatter("%M:%S")
        threshold = stats.mean(y_values) + (2 * stats.stdev(y_values))

        plt.axhline(y=threshold, linestyle='--', color="r")
        plt.gcf().autofmt_xdate()

        plt.title('Number of Packets within each Time Interval', y=1.08)
        plt.xlabel('Time Interval (UTC)')
        plt.ylabel('Number of Packets')
        # plt.gcf().canvas.set_window_title('Number of Packets Line Chart')

        log = "[+] Successfully drawn a line chart.\n"
        tlog.logger(log, out_file)
        plt.savefig('number_of_packets_line_chart')
        plt.show()
    except Exception:
        log = "[-] An error occured when drawing a line chart.\n\n"
        tlog.logger(log, out_file, True)


if __name__ == "__main__":
    draw_graph(extract_data(p_pcap.parse_pcap()))
