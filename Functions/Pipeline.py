from Functions.Optimized_Parser_Labelling import pcap_parser, label_UNSW, label_CICIDS, combine_UNSW, combine_CICIDS
import os
import pandas as pd
import numpy as np
import logging
import glob
import re
import math


def pipeline(in_dir, out_dir, dataset, processed_csv_file):
    """Function: Complete pipeline to parse UNSW or CICIDS PCAPs, combine with flows to label, and produce labeled payload data.
    Input: in_dir: Directory containing the PCAP files/folders
           out_dir: Directory to output the parsed CSVs
           dataset: Either "UNSW" or "CICIDS"
           processed_csv_file: Preprocessed CSV file containing flow information
    Output: CSV file containing labeled payload information from all packets"""
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s -%(message)s")
    logging.info("Checking directory for files ......")
    if not os.path.exists(processed_csv_file):
        print("Pre-processed file not present, please run CSV_data_preprocessing first.")
        return

    if dataset == "UNSW":
        return UNSW_pipeline(in_dir, out_dir, processed_csv_file)
    elif dataset == "CICIDS":
        return CICIDS_pipeline(in_dir, out_dir, processed_csv_file)
    else:
        print("Wrong input for dataset. Please choose from UNSW or CICIDS.")
        return None


def UNSW_pipeline(in_dir, out_dir, processed_csv_file):
    """Function: Complete UNSW pipeline to parse PCAPs, combine with flows to label, and produce labeled payload data.
    Input: in_dir: Directory containing the PCAP folders
           out_dir: Directory to output the parsed CSVs
           processed_csv_file: Preprocessed CSV file containing flow information
    Output: CSV file containing labeled payload information from all packets"""
    if not os.path.exists(in_dir + "/pcaps 22-1-2015/1.pcap"):
        print(
            "PCAP files not found in the current folder. Please enter the correct directory",
            "e.g. /home/username/UNSW-NB15/UNSW-NB15 - pcap files",
        )
        return

    logging.info("Files found. Initiating PCAP Parsing.......")
    pcap_file_list = sorted(glob.glob(in_dir + "/*/*.pcap"), key=numeric_ordering)
    logging.info(f"Expected 80 files, found {len(pcap_file_list)} files.")
    out_file = out_dir + "/pcap_file_csv_parser/"
    os.makedirs(out_file, exist_ok=True)
    logging.info("Parsing UNSW PCAP files .........")
    pcap_parser(pcap_file_list, out_file, 1)
    logging.info("Parsing Completed.......")

    logging.info("Labeling UNSW PCAP files.......")
    pcap_csv = sorted(glob.glob(out_file + "/pcap_csv_*.csv"), key=numeric_ordering)
    logging.info(f"Expected 80 files, found {len(pcap_csv)} files.")
    output_file = out_dir + "/labelled_pcap_file/"
    os.makedirs(output_file, exist_ok=True)
    label_UNSW(pcap_csv, processed_csv_file, output_file, 1)
    logging.info("Labeling Completed.")

    logging.info("Combining labelled files.......")
    in_file = sorted(glob.glob(output_file + "labelled_pcap_csv_*.csv"), key=numeric_ordering)
    logging.info(f"Expected 80 files, found {len(in_file)} files.")
    df_payload = combine_UNSW(in_file, out_dir)

    logging.info("Total Shape of Combined Data Before Processing is: %s", df_payload.shape)
    logging.info("Removing Duplicates ......")
    df_payload.drop_duplicates(inplace=True)

    logging.info("Removing Non-Payload Data Instances (e.g. payload is all zero) .........")
    df_payload.drop(df_payload[df_payload.payload.isnull()].index, inplace=True)
    df_payload = df_payload[~df_payload.payload.str.fullmatch("0+")]

    logging.info("Sorting payloads by stime")
    df_payload.sort_values(by=["stime"], inplace=True, ignore_index=True)
    df_payload.sttl = df_payload.sttl.astype("int32")
    df_payload.dsport = df_payload.dsport.astype("int32")
    df_payload.sport = df_payload.sport.astype("int32")
    df_payload.total_len = df_payload.total_len.astype("int32")
    logging.info("Total Shape of Combined Data After Processing is: %s", df_payload.shape)

    final = out_dir + "/UNSW_final_cleaned_pcap.csv"
    logging.info("Exporting Finalized Version of Data .............")
    df_payload.to_csv(final, index=False)

    logging.info("Process Completed ...................")
    logging.info(f"Final output CSV saved at {final}")
    return df_payload


def CICIDS_pipeline(in_dir, out_dir, processed_csv_file):
    """Function: Complete CICIDS pipeline to parse PCAPs, combine with flows to label, and produce labeled payload data.
    Input: in_dir: Directory containing the PCAP folders
           out_dir: Directory to output the parsed CSVs
           processed_csv_file: Preprocessed CSV file containing flow information
    Output: CSV file containing labeled payload information from all packets"""
    if not os.path.exists(in_dir + "/Monday-WorkingHours.pcap"):
        print("Pcap Files not Found in the current folder. Please enter the correct directory containing the working hours PCAP files.")
        return

    logging.info("Files found. Initiating PCAP Parsing.......")
    pcap_file_list = glob.glob(in_dir + "/*-WorkingHours.pcap")
    logging.info(f"Expected 5 files, found {len(pcap_file_list)} files.")
    out_file = out_dir + "/pcap_file_csv_parser/"
    os.makedirs(out_file, exist_ok=True)
    logging.info("Parsing CICIDS PCAP Files .........")
    pcap_parser(pcap_file_list, out_file, 1)
    logging.info("Parsing Completed.......")

    pcap_csv = glob.glob(out_file + "/pcap_csv_*.csv")
    logging.info(f"Expected 5 files, found {len(pcap_csv)} files.")
    logging.info("Labeling PCAP Files .........")
    output_file = out_dir + "/labelled_pcap_file/"
    os.makedirs(output_file, exist_ok=True)
    label_CICIDS(pcap_csv, processed_csv_file, output_file, 1)
    logging.info("Labeling Completed.")

    logging.info("Combining labelled files.......")
    in_file = glob.glob(output_file + "/labelled_pcap_csv_*.csv")
    logging.info(f"Expected 5 files, found {len(in_file)} files.")
    df_payload = combine_CICIDS(in_file, out_dir)

    logging.info("Total Shape of Combined Data Before Processing is: %s", df_payload.shape)
    logging.info("Removing Non-Payload Data Instances (e.g. payload is all zero) .........")
    df_payload.drop(df_payload[df_payload.payload.isnull()].index, inplace=True)
    df_payload = df_payload[~df_payload.payload.str.fullmatch("0+")]

    logging.info("Sorting payloads by stime")
    df_payload.sort_values(by=["stime"], inplace=True, ignore_index=True)
    df_payload.sttl = df_payload.sttl.astype("int32")
    df_payload.dsport = df_payload.dsport.astype("int32")
    df_payload.sport = df_payload.sport.astype("int32")
    df_payload.total_len = df_payload.total_len.astype("int32")
    logging.info("Total Shape of Combined Data After Processing is: %s", df_payload.shape)

    final = out_dir + "/CICIDS_final_cleaned_pcap.csv"
    logging.info("Exporting Finalized Version of Data .............")
    df_payload.to_csv(final, index=False)

    logging.info("Process Completed ...................")
    logging.info(f"Final output CSV saved at {final}")
    return df_payload


##################################################################################


file_pattern = re.compile(r".*?(\d+).*?")


def numeric_ordering(file):
    match = re.findall(r"\d+", file)
    if not match:
        return math.inf
    return int(match[-1])