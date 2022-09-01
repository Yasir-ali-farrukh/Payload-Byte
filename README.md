# <img src="/Payload-Byte-logo.jpg" width="140" valign="middle" alt="Scapy" />&nbsp; Payload-Byte


<p align="justify"> Payload-Byte is a tool for extracting and labeling packet capture (Pcap) files of modern network intrusion detection datasets.</p>

<p align="justify"> Since packet-based approaches for Network Intrusion Detection (NIDS) suffer from a lack of standardization, resulting in incomparability and reproducibility issues. Moreover, there are no standard labeled datasets available unlike flow-based datasets, forcing researchers to follow bespoke labeling pipelines for individual approaches. Without a standardized baseline, proposed approaches cannot be compared and evaluated with each other. One cannot gauge whether the proposed approach is a methodological advancement or is just being benefited from the proprietary interpretation of the dataset. Payload-Byte addresses the comparability and reproducibility issues by extracting and labeling network packets according to the available meta-data. </p>

<p align="justify"> The function of this tool is to provide a standardized baseline for extracting and labeling PCAP files of available intrusion detection datasets for future reasearch work. </p>

## Processed Datasets
For the ease of future researchers, we have included the processed and labeled payload data of two widely utilized network intrusion detection datasets. They are available under `Data` Folder.

* UNSW-NB15
* CIC-IDS2017

## Usage 

<p align="justify"> There are two different ways through which results can be generated completely. </p>

1. The first one is using `Pipeline.ipynb` notebook which is a pipeline in which you just need to specify the directories of PCAP files and CSV files. Rest will be computed automatically. **Note:** For this approach, you should have enough space in your drive.  
2. The other appraoch is to utilize the functions seperately which is being illustrated in `Individual_approach` folder.

## Citation 
 If you are using our tool, kindly cite our related paper which outlines the details of the tools and its processing. 
 
>@article{Payload,  
>author = "Yasir Ali Farrukh and Irfan Khan and Syed Wali and David Bierbrauer and Nathaniel Bastian",  
>title = "{Payload-Byte: A Tool for Extracting and Labeling Packet Capture Files of Modern Network Intrusion Detection Datasets}",  
>year = "2022",  
>month = "9",  
>url = "https://www.techrxiv.org/articles/preprint/Payload->>Byte_A_Tool_for_Extracting_and_Labeling_Packet_Capture_Files_of_Modern_Network_Intrusion_Detection_Datasets/20714221",  
>doi = "10.36227/techrxiv.20714221.v1"  
>}
 
