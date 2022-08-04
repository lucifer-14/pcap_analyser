"""
Script: graph_analysis.py
Description: Extract data from PCAP file and draw a line chart of
            number of packets between each time intervals
Author: Thar Htet Nyan
Date: Auguest 2022
"""


import statistics as stats
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdt
import parse_pcap as p_pcap


def extract_data(pcap_data: tuple) -> dict:
    """ Extract time intervals and packet counts between each time interval.
        Return dictionary of time_intervals(key) and packet counts(value)
    """

    ts_list, _ = pcap_data
    start_time = ts_list[0]
    interval = 5
    data: dict = {}
    # time_interval = f"{start_time} -> {start_time+interval}"
    time_interval = start_time
    print("[*] Extracting data to create a line chart.\n")
    for timestamp in ts_list:
        if timestamp > start_time+interval:
            start_time += interval
            # time_interval = f"{start_time} -> {start_time+interval}"
            time_interval = start_time+interval
        if time_interval in data:
            data[time_interval] += 1
        else:
            data.setdefault(time_interval, 1)
    print("[+] Successfully extracted data to create a line chart.\n")

    return data


def draw_graph(pcap_data: tuple) -> None:
    """ Draw a line chart from extracted data
    """

    data = extract_data(pcap_data)

    print("[*] Drawing a line chart.\n")
    x_values = list(data)
    y_values = list(data.values())
    x_dates = [datetime.utcfromtimestamp(i) for i in x_values]

    plt.plot(x_dates, y_values)
    plt.format_xdata = mdt.DateFormatter("%M:%S")
    threshold = stats.mean(y_values) + (2*stats.stdev(y_values))

    plt.axhline(y=threshold, linestyle='--', color="r")
    plt.gcf().autofmt_xdate()

    plt.title('Number of Packets within each Time Interval', y=1.08)
    plt.xlabel('Time Interval (UTC)')
    plt.ylabel('Number of Packets')
    # plt.gcf().canvas.set_window_title('Number of Packets Line Chart')

    print("[+] Successfully drawn a line chart.\n")
    plt.savefig('number_of_packets_line_chart')
    plt.show()


if __name__ == "__main__":
    draw_graph(p_pcap.parse_pcap(p_pcap.PCAP_FILE))
