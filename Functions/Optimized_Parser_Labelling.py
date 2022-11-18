import logging
import os
from datetime import datetime, timedelta
import traceback

import pandas as pd
import scapy.all as sc
import scapy


def pcap_parser(pcap_files, out_file_csv, file_num):
    """Function: Extract information from Pcap files and saves into a .CSV format
    Input: pcap_files: List of the PCAP files to be parsed
           out_file_csv: Directory to output the parsed CSVs
           file_num: File number that increments to give each labeled CSV a unique name.
    Output: CSV file containing all information from packet"""
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s -%(message)s")
    for pcap_file in pcap_files:
        logging.info("Reading input file:  %s", pcap_file)
        packet_counter = 0
        skipped_counter = 0
        all_rows = []
        pcap = sc.PcapReader(pcap_file)
        while True:
            try:
                f = pcap.read_packet()
                if sc.IP in f:
                    i2s = {
                        0: "ip",
                        1: "icmp",
                        2: "igmp",
                        3: "ggp",
                        6: "tcp",
                        8: "egp",
                        11: "nvp",
                        12: "pup",
                        14: "emcon",
                        17: "udp",
                        20: "hmp",
                        27: "rdp",
                        33: "sep",
                        41: "ipv6",
                        46: "rsvp",
                        47: "gre",
                        53: "swipe",
                        55: "mobile",
                        61: "any",
                        63: "any",
                        66: "rvd",
                        68: "any",
                        77: "sun-nd",
                        81: "vmtp",
                        82: "secure-vmtp",
                        86: "dgp",
                        89: "ospf",
                        91: "larp",
                        93: "ax.25",
                        94: "ipip",
                        95: "micp",
                        96: "aes-sp3-d",
                        97: "etherip",
                        98: "encap",
                        99: "any",
                        100: "gmtp",
                        102: "pnni",
                        103: "pim",
                        109: "snp",
                        125: "fire",
                        126: "crtp",
                        127: "crudp",
                        128: "sccopmce",
                        129: "iplt",
                        130: "sps",
                        131: "pipe",
                        132: "sctp",
                        135: "fc",
                        253: "ib",
                        255: "unas",
                    }

                    if f[1].proto in i2s:
                        proto_m = i2s[f[1].proto]
                    else:
                        proto_m = "others"

                    src_ip = f["IP"].src  # Src Ip
                    dst_ip = f["IP"].dst  # Dst Ip
                    total_len = f["IP"].len  # Total Length
                    sttl = f["IP"].ttl
                    epoch = f.time

                    # Find the first protocol in f that has a valid payload or return None
                    payload_protocols = [sc.UDP, sc.TCP, sc.ICMP]
                    payload_protocol = next((element for element in payload_protocols if element in f), None)

                    if payload_protocol:
                        payload = bytes(f[payload_protocol].payload).hex()
                    else:
                        payload = bytes(f.load).hex()

                    try:
                        sport = f.sport
                        dport = f.dport
                    except AttributeError:
                        sport = 0
                        dport = 0

                    if proto_m == "sctp":
                        # After Analyzing the files, get to know CSV files of UNSW didnt extracted its port
                        sport = 0
                        dport = 0
                elif f.haslayer(sc.ARP):
                    proto_m = "arp"
                    src_ip = f["ARP"].psrc  # Soruce Ip
                    dst_ip = f["ARP"].pdst  # Dest IP
                    epoch = f.time
                    if len(f.layers()) > 2:
                        payload = f.getlayer(sc.ARP).load.hex()
                    else:
                        payload = 0
                    sttl = 0
                    sport = 0
                    dport = 0
                    total_len = 0
                else:
                    skipped_counter += 1
                    layers = f.layers()
                    # Ignore any LLC, IPv6, and Raw packets
                    if scapy.layers.l2.LLC in layers or scapy.layers.inet6.IPv6 in layers:
                        continue
                    if len(layers) == 2 and scapy.packet.Raw == layers[1]:
                        continue

                    # We've hit an unknown packet type, i.e. is not TCP/UDP/ARP/LLC/RAW, so display and stop
                    print("Unknown packet type received. Is this CICIDS2017 or UNSW-NB15 data?  Stopping.")
                    print(f.layers())
                    print(f.show())
                    return

                all_rows.append([packet_counter, epoch, src_ip, sport, dst_ip, dport, proto_m, sttl, total_len, payload])
                packet_counter += 1
                if packet_counter % 100000 == 0:
                    logging.info(f"Done with {packet_counter} Packets")
            except EOFError:
                logging.info(f"Done reading {pcap_file}")
                break
            except Exception as e:
                print(f"Unknown Exception during parsing of {pcap_file}, aborting parsing: ", e)
                traceback.print_exc()
                return
        out = pd.DataFrame(
            all_rows,
            columns=[
                "frame_num",
                "stime",
                "srcip",
                "sport",
                "dstip",
                "dsport",
                "protocol_m",
                "sttl",
                "total_len",
                "payload",
            ],
        )

        out["stime"] = out["stime"].astype(float).round().astype(int)
        out["t_delta"] = out["stime"] - out["stime"].shift(1)
        out.t_delta[0] = 0
        logging.info(f"Skipped {skipped_counter} unparsable packets.")
        logging.info("Exporting CSV File#%s", file_num)
        csv_file = out_file_csv + "pcap_csv_" + str(file_num) + ".csv"
        os.makedirs(out_file_csv, exist_ok=True)
        out.to_csv(csv_file, index=False)
        print(out.protocol_m.value_counts())
        file_num += 1


def label_UNSW(pcap_csv, UNSW_csv, output_file, file_num):
    """Function: Label PCAP by combining parsed PCAP CSV with preprocessed CSV.
    Input: pcap_csv: List of PCAP_csv files
           UNSW_csv: UNSW preprocessed file
           output_file: The directory to save the labelled output.
           file_num: File number that increments to give each labeled CSV a unique name.
    Output: CSV file containing all information from packet along with attack labels"""

    logging.info("Reading Pre-processed UNSW CSV_file...")
    df_flow = pd.read_csv(UNSW_csv, low_memory=False)
    df_flow = df_flow[["stime", "t_delta", "ltime", "dur", "srcip", "dstip", "dsport", "sport", "sttl", "proto", "attack_cat", "label"]]

    # Rename preprocessed protocol column to match pcap protocol column
    df_flow.rename(columns={"proto": "protocol_m"}, inplace=True)
    # Calculate the max of ltime and (stime + dur) because they aren't consistent
    df_flow["ltime2"] = (df_flow.stime + df_flow.dur).round().astype("int32")
    df_flow["ltime_max"] = df_flow[["ltime", "ltime2"]].max(axis=1)
    # Convert any hex values to decimal
    df_flow.loc[:, "dsport"] = df_flow.dsport.apply(lambda x: int(x, base=16) if x.startswith("0x") else x)
    df_flow.loc[:, "sport"] = df_flow.sport.apply(lambda x: int(x, base=16) if x.startswith("0x") else x)
    # Force any remaining non-numeric values to become NaN
    d = pd.to_numeric(df_flow.dsport, errors="coerce")
    s = pd.to_numeric(df_flow.sport, errors="coerce")
    # Convert any NaN ports to 0
    d[d.isna()] = 0
    s[s.isna()] = 0
    # Change df_flow datatypes
    df_flow.dsport = d
    df_flow.sport = s
    # PCAPs for ICMP are all port 0 but flows have other values, so reset all the preprocessed flows to zero
    df_flow.loc[df_flow.protocol_m == "icmp", ["sport", "dsport"]] = 0

    for pcap_file in pcap_csv:
        logging.info("Reading Parsed_Pcap_file_%s...", file_num)
        df_pcap_csv = pd.read_csv(pcap_file, index_col=0, low_memory=False)

        # Merge based on the shared columns
        combine1 = pd.merge(df_pcap_csv, df_flow, how="left", on=["srcip", "dstip", "dsport", "sport", "protocol_m"], suffixes=["", "_flow"])
        # Invert the dest/source to capture return traffic
        combine2 = pd.merge(
            df_pcap_csv,
            df_flow,
            how="left",
            left_on=["srcip", "dstip", "dsport", "sport", "protocol_m"],
            right_on=["dstip", "srcip", "sport", "dsport", "protocol_m"],
            suffixes=["", "_flow"],
        )
        combine = pd.concat([combine1, combine2])

        # Remove any excess columns
        combine.drop(columns=["ltime", "sttl_flow", "dur", "ltime2", "srcip_flow", "dstip_flow", "dsport_flow", "sport_flow"], inplace=True)

        # Drop any packets that did not match a flow
        combine = combine[~combine.label.isna()]

        # Drop any rows that do not have match flow times
        combine = combine[(combine["stime_flow"] <= combine["stime"]) & (combine["stime"] <= combine["ltime_max"])]

        combine.drop_duplicates(inplace=True)

        print("*********Labelled_File_%s_Protocols*************" % file_num)
        print(combine.protocol_m.value_counts())
        print("************************************************")

        csv_out = output_file + "labelled_pcap_csv_" + str(file_num) + ".csv"
        combine.to_csv(csv_out, index=False)
        file_num += 1


def combine_UNSW(in_file_path, out_path):
    """Function: Concatenate all of the UNSW files together into a single CSV.
    Input: in_file_path: List of labelled csv files
           out_path: Directory to save the combined_labelled_pcap_csv.csv file.
    Output: A single dataframe containing the combined information all of the files."""
    combine = pd.DataFrame(
        columns=[
            "stime",
            "t_delta",
            "srcip",
            "sport",
            "dstip",
            "dsport",
            "protocol_m",
            "payload",
            "total_len",
            "label",
            "attack_cat",
        ]
    )
    for files in in_file_path:
        df = pd.read_csv(files)
        combine = pd.concat([combine, df], axis=0, ignore_index=True)
        print(combine.shape)
    csv_out = out_path + "/combined_labelled_pcap_csv.csv"
    logging.info("Exporting_combined_csv_file....")
    combine.to_csv(csv_out, index=False)
    return combine


def combine_CICIDS(in_file_path, out_path):
    """Function: Concatenate all of the CICIDS files together into a single CSV.
    Input: in_file_path: List of labelled csv files
           out_path: Directory to save the combined_labelled_pcap_csv.csv file.
    Output: A single dataframe containing the combined information all of the files."""
    combine = pd.DataFrame(
        columns=[
            "stime",
            "t_delta",
            "srcip",
            "sport",
            "dstip",
            "dsport",
            "protocol_m",
            "sttl",
            "total_len",
            "payload",
            "stime",
            "label",
        ]
    )
    for files in in_file_path:
        df = pd.read_csv(files)
        combine = pd.concat([combine, df], axis=0, ignore_index=True)
        print(combine.shape)
    csv_out = out_path + "/combined_labelled_pcap_csv.csv"
    logging.info(f"Exporting_combined_csv_file at {csv_out}....")
    combine.to_csv(csv_out, index=False)
    return combine


def label_CICIDS(pcap_csv, CICIDS_csv, output_file, file_num):
    """Function: Label PCAP by combining parsed PCAP CSV with preprocessed CSV.
    Input: pcap_csv: List of PCAP_csv files
           CICIDS_csv: CICIDS preprocessed file
           output_file: The directory to save the labelled output.
           file_num: File number that increments to give each labeled CSV a unique name.
    Output: CSV file containing all information from packet along with attack labels"""
    logging.info("Reading Pre-processed CICIDS CSV_file...")
    df_flow = pd.read_csv(CICIDS_csv)
    df_flow = df_flow[
        [
            "Timestamp",
            "Flow Duration",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Label",
        ]
    ]
    df_flow.rename(
        columns={
            "Timestamp": "stime",
            "Flow Duration": "duration",
            "Source IP": "srcip",
            "Source Port": "sport",
            "Destination IP": "dstip",
            "Destination Port": "dsport",
            "Protocol": "protocol_m",
            "Label": "label",
        },
        inplace=True,
    )

    # Record the resolution for later matching
    df_flow.loc[df_flow.stime.str.count(":") == 1, "offset"] = 60
    df_flow.loc[df_flow.stime.str.count(":") == 2, "offset"] = 1

    df_flow["stime"] = df_flow["stime"].apply(
        lambda x: (datetime.strptime(x + " -0300", "%d/%m/%Y %H:%M %z"))
        if x.count(":") == 1
        else (datetime.strptime(x + " -0300", "%d/%m/%Y %H:%M:%S %z"))
    )

    # Timestamps are listed 3/7/2017 2:55, without AM/PM indicators, so any time between 1 and 7 AM ADT (4 and 11 AM UTC) are actually PM
    # Datetime was instantiated with timezone info, so .hour is already in the -0300 timezone
    df_flow["stime"] = df_flow["stime"].apply(
        lambda x: int((x + timedelta(hours=12)).timestamp()) if (x.hour >= 1) & (x.hour <= 7) else int(x.timestamp())
    )
    df_flow = df_flow.sort_values(by="stime")

    df_flow["protocol_m"] = df_flow["protocol_m"].astype(str)
    df_flow["protocol_m"] = df_flow["protocol_m"].apply(lambda x: x.replace("6.0", "tcp"))
    df_flow["protocol_m"] = df_flow["protocol_m"].apply(lambda x: x.replace("17.0", "udp"))
    df_flow["protocol_m"] = df_flow["protocol_m"].apply(lambda x: x.replace("0.0", "other"))
    df_flow.rename(columns={"stime": "stime_flow"}, inplace=True)
    for pcap_file in pcap_csv:
        logging.info("Reading Parsed_Pcap_file_%s ......", file_num)
        df_pcap_csv = pd.read_csv(pcap_file, index_col=0)

        # PCAPs are labeled by actual protocol, but flow only has tcp/udp/other labels.
        df_pcap_csv["protocol_m"] = df_pcap_csv["protocol_m"].apply(lambda x: x if x == "tcp" or x == "udp" else "other")

        # Merge based on the shared columns keeping every payload and adding flow data for every matches
        # Merge duplicates the PCAP row for each matching df_flow row
        combine1 = pd.merge(df_pcap_csv, df_flow, how="left", on=["srcip", "dstip", "dsport", "sport", "protocol_m"])
        # Invert the dest/source to capture return traffic
        combine2 = pd.merge(
            df_pcap_csv,
            df_flow,
            how="left",
            left_on=["srcip", "dstip", "dsport", "sport", "protocol_m"],
            right_on=["dstip", "srcip", "sport", "dsport", "protocol_m"],
            suffixes=["", "_flow"],
        )
        combine = pd.concat([combine1, combine2])
        combine.drop_duplicates(inplace=True)

        # Drop any rows that are do not have matching times, i.e. keep only rows that the payload timestamp is after the flow started and before the flow ends
        # stime is measured in seconds
        # stime_flow has resolution of either 1 second or 60 seconds, recorded in offset
        # duration is measured in microseconds
        combine = combine[
            (combine["stime_flow"] - combine["offset"] <= combine["stime"])
            & (combine["stime"] <= combine["stime_flow"] + combine["offset"] + combine["duration"] / 1e6)
        ]

        # Rename to attack_cat for consistency with UNSW
        combine.rename(columns={"label": "attack_cat"}, inplace=True)

        # Label is 0 for benign and 1 for anything else
        combine["label"] = 0
        combine.loc[combine.attack_cat != "BENIGN", "label"] = 1

        print("*********Labelled_File_%s_Protocols*************" % file_num)
        print(combine.protocol_m.value_counts())
        print(combine.shape)
        print("************************************************")

        csv_out = output_file + "labelled_pcap_csv_" + str(file_num) + ".csv"
        combine.to_csv(csv_out, index=False)
        file_num += 1