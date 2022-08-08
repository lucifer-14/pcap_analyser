"""
Script: pcap_analyser.py
Description: Analyses the PCAP file. Show Packet Types information, TO and FROM email
            addresse, Traffic Information. Create KML file to locate destination IP addresses.
            Draw a line chart to display number of packets within each time interval
Author: Thar Htet Nyan
Date: August 2022
"""


import argparse
import parse_pcap as p_pcap
import analyse_packets as ap
import geolocation as gl
import graph_analysis as ga


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--pcap-file', type=str,
                        help="pcap file name to read",
                        default=p_pcap.PCAP_FILE)
    parser.add_argument('-ptt', '--packet_type_table',
                        help="display packet type information",
                        action='store_true')
    parser.add_argument('-ap', '--analyse_packets',
                        help="analyse the packets and show information",
                        action='store_true')
    parser.add_argument('-t', '--traffic-file', type=str,
                        help="output filename to store traffics",
                        default=ap.TRAFFIC_FILE)
    parser.add_argument('-g', '--geo-db', type=str,
                        help="geolite database name",
                        default=gl.GEOLOCATION_DB)
    parser.add_argument('-gk', '--geolocation_kml',
                        help="make a KML file that shows locations of destination ip addresses",
                        action='store_true')
    parser.add_argument('-ga', '--graph_analysis',
                        help="display a line chart of number of packets within each time interval",
                        action='store_true')
    arg = parser.parse_args()

    ap.TRAFFIC_FILE = arg.traffic_file
    gl.GEOLOCATION_DB = arg.geo_db

    if arg.packet_type_table or arg.analyse_packets or arg.geolocation_kml or arg.graph_analysis:
        pcap_data = p_pcap.parse_pcap(arg.pcap_file)
        eth_data = p_pcap.parse_inet_proto(pcap_data)

    if arg.packet_type_table:
        p_pcap.tabulate_data(pcap_data)

    if arg.analyse_packets:
        ap.display_analysed_data(eth_data)

    if arg.geolocation_kml:
        gl.create_kml_file(ap.extract_traffics(eth_data))

    if arg.graph_analysis:
        ga.draw_graph(pcap_data)
