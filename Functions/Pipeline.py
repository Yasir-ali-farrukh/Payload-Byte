from Functions.Optimized_Parser_Labelling import pcap_parser, label_UNSW, label_CICIDS, combine_UNSW, combine_CICIDS
import os
import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import LabelEncoder
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
    out_file = out_dir + "/pcap_file_csv_parser/"
    os.makedirs(out_file, exist_ok=True)
    logging.info("Parsing UNSW PCAP files .........")
    pcap_parser(pcap_file_list, out_file, 1)
    logging.info("Parsing Completed.......")

    logging.info("Labeling UNSW PCAP files.......")
    pcap_csv = sorted(glob.glob(out_file + "/pcap_csv_*.csv"), key=numeric_ordering)
    output_file = out_dir + "/labelled_pcap_file/"
    os.makedirs(output_file, exist_ok=True)
    label_UNSW(pcap_csv, processed_csv_file, output_file, 1)
    logging.info("Labeling Completed.")

    logging.info("Combining labelled files.......")
    in_file = sorted(glob.glob(output_file + "labelled_pcap_csv_*.csv"), key=numeric_ordering)
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
    out_file = out_dir + "/pcap_file_csv_parser/"
    os.makedirs(out_file, exist_ok=True)
    logging.info("Parsing CICIDS PCAP Files .........")
    pcap_parser(pcap_file_list, out_file, 1)
    logging.info("Parsing Completed.......")

    pcap_csv = glob.glob(out_file + "/pcap_csv_*.csv")
    logging.info("Labeling PCAP Files .........")
    output_file = out_dir + "/labelled_pcap_file/"
    os.makedirs(output_file, exist_ok=True)
    label_CICIDS(pcap_csv, processed_csv_file, output_file, 1)
    logging.info("Labeling Completed.")

    logging.info("Combining labelled files.......")
    in_file = glob.glob(output_file + "/labelled_pcap_csv_*.csv")
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


def payload_to_bytes(df, dim):
    """Convert Labelled PCAP file's payload data(hex) into byte (int)
    Input:  df: Labelled Pcap file Data in panda Dataframe
            dim: The size of the payload
    Output: X: Payload data in int form in range of 0-255 in dim Columns
            Y: Attack Category for each data"""
    df_temp = df
    X = df_temp["payload"].to_numpy().reshape((-1, 1))
    X = np.apply_along_axis(payload_transform, 1, X, dim)
    y = np.array(df_temp["label"]).reshape((-1, 1))
    return X, y


def payload_transform(x, dims):
    byte_array = bytes.fromhex(x[0])
    byte_lst = list(byte_array)
    if len(byte_lst) < dims:
        output = np.pad(byte_lst, (0, dims - len(byte_lst)), "constant")
    else:
        output = np.array(byte_lst[0:dims].copy())
    output = np.abs(output.astype("int32"))
    # output = np.abs(output.astype(float)) / 255
    # return output.astype(float)
    return output


##################################################################################


def transform(df, out_dir):
    """Encode the protocol, payload, ttl, total_length, and duration
    Input:  df: Labelled Pcap file Data in panda Dataframe
            dim: The size of the payload
    Output: X: Payload data in int form in range of 0-255 in dim Columns
            Y: Attack Category for each data"""
    le = LabelEncoder()
    df["protocol_m"] = le.fit_transform(df["protocol_m"])
    X_tr, Ytrain = payload_to_bytes(df, 1500)
    X_tr = np.column_stack((X_tr, np.array(df.iloc[:, "ttl"])))
    X_tr = np.column_stack((X_tr, np.array(df.iloc[:, "total_len"])))
    X_tr = np.column_stack((X_tr, np.array(df.iloc[:, "protocol"])))
    X_tr = np.column_stack((X_tr, np.array(df.iloc[:, "t_delta"])))
    name = []
    for x in range(1, 1501):
        name.append("payload_byte_" + str(x))
    name.append("ttl")
    name.append("total_len")
    name.append("protocol")
    name.append("t_delta")
    final = pd.DataFrame(X_tr, columns=name)
    final["label"] = Ytrain
    final.to_csv(out_dir + "Converted_data.csv", index=False)
    return final


file_pattern = re.compile(r".*?(\d+).*?")


def numeric_ordering(file):
    match = re.findall(r"\d+", file)
    if not match:
        return math.inf
    return int(match[-1])