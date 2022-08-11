"""
Script: geolocation.py
Description: Extract data from PCAP file and make a KML file of
            locations of each destination IP address
Author: Thar Htet Nyan
Date: July 2022
"""

import os
import sys
from io import TextIOWrapper
import simplekml
import geoip2.database
import geoip2.errors
import parse_pcap as p_pcap
import analyse_packets as ap
import tlogger as tlog


GEOLOCATION_DB = 'GeoLite2-City_20190129.mmdb'


def get_geolocation(traffics_dict: dict, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> dict:
    """Return geo_location_dict which contains IP addresses and
    their packet counts, longitude, latitude, country and city names
    """

    geo_location_dict: dict = {}  # stores geo_location data using IP addresses as a key
    geo_info_list = []      # stores geo_info obtained from geoip2.database.Reader and packet counts
    log = "[*] Extracting geolocation information from destination IP addresses.\n"
    tlog.logger(log, out_file)
    try:
        g_reader = geoip2.database.Reader(GEOLOCATION_DB)
        for traffic_count, traffics_list in traffics_dict.items():
            for traffic in traffics_list:
                try:
                    geo_info_list.append([g_reader.city(traffic[1]), traffic_count])
                except geoip2.errors.AddressNotFoundError:
                    geo_info_list.append(['', ''])  # append an empty list if not found
                except TypeError as err:
                    log = f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n'
                    tlog.logger(log, out_file, True)
                    sys.exit()
    except geoip2.errors.GeoIP2Error as err:
        log = f'\n[-] {err.__class__}: {err.__class__.__name__}\n\n'
        sys.stderr.write(log)
        print(log, file=out_file, flush=True)
        sys.exit()
    except FileNotFoundError:
        log = f'\n[-] GeoLocation file: {GEOLOCATION_DB} - NOT Found!\n\n'
        sys.stderr.write(log)
        print(log, file=out_file, flush=True)
        sys.exit()

    # creates geo_location_dict with ip address as key
    for geo_info, pkt_count in geo_info_list:
        # checks if there is information
        if geo_info:
            # checking whether the information of ip address is already extracted or not
            # if already extracted, just add the packet count
            if geo_info.traits.ip_address in geo_location_dict:
                geo_location_dict[geo_info.traits.ip_address]['packet_count'] += pkt_count
                continue

            # prepare data dict to store packet count(key), longitude(key), latitude(key),
            # country(key) (if exists), city(key) (if exists)
            data = {
                'packet_count': pkt_count,
                'longitude': geo_info.location.longitude,
                'latitude': geo_info.location.latitude,
                'country': geo_info.country.names['en']
            }

            if geo_info.city.names:
                data.update({"city": geo_info.city.names['en']})
            else:
                data.update({"city": ''})

            # update the geo_location dict with ip address (key) and data (value)
            geo_location_dict.update({geo_info.traits.ip_address: data})

    log = "[+] Successfully extracting geolocation information from destination IP addresses.\n"
    tlog.logger(log, out_file)
    return geo_location_dict


def create_kml_file(traffics_dict: dict, out_file: TextIOWrapper = p_pcap.OUT_FILE) -> None:
    """ Create KML file from IP address dictionary
    """

    geo_location_dict = get_geolocation(traffics_dict)
    log = "[*] Creating a KML file with geolocation information.\n"
    tlog.logger(log, out_file)
    kml = simplekml.Kml()
    for ip_addr, geo_location in geo_location_dict.items():
        description = f"Country: {geo_location['country']}"
        if geo_location['city']:
            description += f"\nCity: {geo_location['city']}"
        description += f"\nPacket Count: {geo_location['packet_count']}"
        kml.newpoint(name=ip_addr,
                    coords=[(
                        geo_location['longitude'],
                        geo_location['latitude']
                        )],
                    description=description)

    filename, _ = os.path.splitext(p_pcap.PCAP_FILE)
    res_filename = filename + "_result.kml"
    kml.save(res_filename)
    log = kml.kml()
    tlog.logger(log, out_file)
    log = f"[+] Successfully created a KML file - {res_filename} with geolocation information.\n"
    tlog.logger(log, out_file)


if __name__ == "__main__":
    create_kml_file(ap.extract_traffics(p_pcap.parse_inet_proto(p_pcap.parse_pcap())))
    p_pcap.OUT_FILE.close()
