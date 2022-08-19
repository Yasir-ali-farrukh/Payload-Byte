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
2. The other appraoch is to utilize the functions seperately which is being illustrated in `Individual approach` folder.


