import scapy.all as sc
import numpy as np
import logging
import pandas as pd
from datetime import datetime
import os

""" Function: Extract information from Pcap files and saves into a .CSV format
    Input: List of Pcap file's directory & File_number (used for labelling the output file)
    Output: CSV file containing all information from packet"""

## pcap_file= ['E:/UNSW-NB15 Dataset/Pcap-files-17-2-2015/4.pcap','E:/UNSW-NB15 Dataset/Pcap-files-17-2-2015/5.pcap' ..... ]
## out_file= 'G:/UNSW_result/pcap_file_csv_parser/'
## file_num= 4 ; Number of file that you are loading like we are giving 4 and 5 pcap file so this number is 4.

def pcap_parser(pcap_file,out_file_csv,file_num):
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s -%(message)s')
    for pcap in pcap_file:
        #logging.info("******************************************************************************")
        logging.info("Reading input file:  %s",pcap)
        n=1
        all_rows=[]
        packet=sc.PcapReader(pcap)
        try:
            while True:
                f=packet.read_packet()
                try: 
                    if f.proto!=2054:
                        try:
                            proto_m=f[1].get_field("proto").i2s[f[1].proto]    ### Main Protocl
                        except:
                            if f[1].proto==89:
                                proto_m='ospf'
                            elif f[1].proto==132:
                                proto_m="sctp"
                            elif f[1].proto==47:
                                proto_m="gre"
                            elif f[1].proto==33:
                                proto_m="sep"
                            elif f[1].proto==103:
                                proto_m="pim"
                            elif f[1].proto==2:
                                proto_m="igmp"
                            elif f[1].proto==55:
                                proto_m="mobile"
                            elif f[1].proto==53:
                                proto_m="swipe"
                            elif f[1].proto==77:
                                proto_m="sun-nd"
                            elif f[1].proto==255:
                                proto_m="unas"
                            elif f[1].proto==253:
                                proto_m="ib"
                            elif f[1].proto==135:
                                proto_m="fc"
                            elif f[1].proto==131:
                                proto_m="pipe"
                            elif f[1].proto==128:
                                proto_m="sccopmce"
                            elif f[1].proto==127:
                                proto_m="crudp"
                            elif f[1].proto==125:
                                proto_m="fire"
                            elif f[1].proto==126:
                                proto_m="crtp"
                            elif f[1].proto==129:
                                proto_m="iplt"
                            elif f[1].proto==130:
                                proto_m="sps"
                            elif f[1].proto==93:
                                proto_m="ax.25"   
                            elif f[1].proto==46:
                                proto_m="rsvp"
                            elif f[1].proto==109:
                                proto_m="snp"
                            elif f[1].proto==81:
                                proto_m="vmtp"
                            elif f[1].proto==11:
                                proto_m="nvp"
                            elif f[1].proto==14:
                                proto_m="emcon"
                            elif f[1].proto==82:
                                proto_m="secure-vmtp"
                            elif f[1].proto==41:
                                proto_m="ipv6"   
                            elif f[1].proto==26:
                                proto_m="leaf-2"
                            elif f[1].proto==100:
                                proto_m="gmtp"
                            elif f[1].proto==94:
                                proto_m="ipip"
                            elif f[1].proto==102:
                                proto_m="pnni"
                            elif f[1].proto==97:
                                proto_m="etherip"
                            elif f[1].proto==86:
                                proto_m="dgp"
                            elif f[1].proto==95:
                                proto_m="micp"
                            else:
                                proto_m='others'
                        try:
                            proto_s=f[2].get_field("dport").i2s[f[2].dport] ## Sub protocol
                        except:
                            if proto_m=="gre":
                                proto_s="nhrp"
                            else:
                                proto_s=f[1].proto ## Sub protocol
                        Sttl=f['IP'].ttl ### Sttl
                        src_ip=f['IP'].src ## Src Ip
                        dst_ip=f['IP'].dst ## Dst Ip
                        total_len=f['IP'].len ## Total Length
                        epoch=f.time
                        try:
                            payload=bytes(f.load).hex()
                        except:
                            payload=bytes(f[2].payload).hex()
                        try:
                            sport=f.sport
                            dport=f.dport
                            if proto_m=="sctp":  # After Analyzing the files, get to know CSV files of UNSW didnt extracted its port
                                sport=0
                                dport=0
                        except:
                            sport=0
                            dport=0
                    else:
                        proto_m="arp"
                        proto_s="arp"
                        Sttl=0
                        src_ip=f['ARP'].psrc ## Soruce Ip 
                        dst_ip=f['ARP'].pdst ## Dest IP
                        total_length=0
                        epoch=f.time
                        if len(f.layers())>2:
                            payload=f[2].load.hex()
                        else:
                            payload=0
                        sport=0
                        dport=0
                    temp_list=[n,epoch,src_ip,sport,dst_ip,dport,proto_m,proto_s,Sttl,total_len,payload]
                    all_rows.append(temp_list)
                    n+=1
                    if n%100000==0:
                        logging.info("Done with %s Packets",n)
                except Exception as e:
                    #print("Unknown",e)
                    continue
        except Exception as e:
            print(e)
        out=pd.DataFrame(all_rows,columns=['frame_num','stime','srcip','sport','dstip','dsport','protocol_m','protocol_s','sttl','total_len','payload'])
        ## Generating t_delta Column
        out['t_delta']=out['stime'] - out['stime'].shift(1)
        out.t_delta[0]=0
        out['t_delta']=out['t_delta'].astype(float)
        out['ltime']=out['stime']+out['t_delta']

        out.ltime=out.ltime.astype(float)
        out['ltime']=out['ltime'].round()
        out.ltime=out.ltime.astype(int)
        out.stime=out.stime.astype(float)
        out['stime']=out['stime'].round()
        out.stime=out.stime.astype(int)

        logging.info("Exporting CSV File#%s",file_num)
        csv_file=out_file_csv+"pcap_csv_"+str(file_num)+".csv"
        out.to_csv(csv_file)
        file_num+=1
        
        
        
""" Function: Label Pcap_file utilizng pcap_file CSV and preprocessed UNSW provided CSV file
    Input: List of Pcap_csv file's directory & File_number (used for labelling the output file)
    Output: CSV file containing all information from packet along with attack labels"""        

## pcap_csv=['G:/UNSW_result/pcap_file_csv_parser/pcap_csv_1.csv','G:/UNSW_result/pcap_file_csv_parser/pcap_csv_2.csv'......]
## UNSW_csv="E:/UNSW-NB15 Dataset/UNSW-NB15-CSV-Files/Preprocessed-CSV/UNSW-NB15_processed.csv"
## output_file="G:/UNSW_result/Labelled_pcap_file/"
## file_num= 1 ; Number of file that you are loading like we are giving 1 and 2 pcap_csv file so this number is 1.
        
def label(pcap_csv,UNSW_csv,output_file,file_num):
    logging.info("Reading Pre-processed UNSW CSV_file...")
    df_UNSW_csv=pd.read_csv(UNSW_csv)
    df_pre=df_UNSW_csv[['stime','ltime','srcip','dstip','dsport','sport','sttl','proto','dur','attack_cat','label']]
    
    for pcap_file in pcap_csv:
        logging.info("Reading Parsed_Pcap_file_%s...",file_num)
        df_pcap_csv=pd.read_csv(pcap_file,index_col=0)
        stime=df_pcap_csv.stime[0]
        ltime=int(df_pcap_csv.stime.tail(1))
        df_red=df_pre[(df_pre['stime']>=stime) & (df_pre['stime']<=ltime)]
        combine=df_pcap_csv.merge(df_red, left_on=['stime','ltime','srcip','dstip','dsport','sport','sttl','protocol_m'], right_on=['stime','ltime','srcip','dstip','dsport','sport','sttl','proto'])
        
        a=df_red[(df_red.proto=='icmp')]
        b=df_pcap_csv[(df_pcap_csv.protocol_m=='icmp')]
        c=b.merge(a, left_on=['stime','ltime','srcip','dstip','sttl','protocol_m'], right_on=['stime','ltime','srcip','dstip','sttl','proto'])
        c.drop(columns=['dsport_y','sport_y'],inplace=True)
        c.rename(columns = {'dsport_x':'dsport', 'sport_x':'sport'}, inplace = True)
        combine=combine.append(c, ignore_index=True)
        
        print("*********Labelled_File_%s_Protocols*************"%file_num)
        print(combine.proto.value_counts())
        print("************************************************")
        
        csv_out=output_file+"labelled_pcap_csv_"+str(file_num)+".csv"
        combine.to_csv(csv_out,index=False)
        file_num+=1
        
    
        
def combine(in_file_path,out_path):
    combine=pd.DataFrame(columns=['frame_num', 'stime', 'srcip', 'sport', 'dstip', 'dsport', 'protocol_m',
       'protocol_s', 'sttl', 'total_len', 'payload', 't_delta', 'ltime',
       'proto', 'dur', 'attack_cat', 'label'])
    for files in in_file_path:
        df=pd.read_csv(files)
        combine=combine.append(df, ignore_index=True)
        print(combine.shape)
    csv_out=out_path+"combined_labelled_pcap_csv.csv"
    logging.info("Exporting_combined_csv_file....")
    combine.to_csv(csv_out,index=False)
    return combine
 

def combine_CICIDS(in_file_path,out_path):
    combine=pd.DataFrame(columns=['srcip', 'sport', 'dstip', 'dsport', 'protocol_m',
     'sttl', 'total_len', 'payload', 't_delta', 'stime','label'])
    for files in in_file_path:
        df=pd.read_csv(files)
        combine=combine.append(df, ignore_index=True)
        print(combine.shape)
    csv_out=out_path+"combined_labelled_pcap_csv.csv"
    logging.info("Exporting_combined_csv_file....")
    combine.to_csv(csv_out,index=False)
    return combine    


    
def label_CICIDS(pcap_csv,CICIDS_csv,output_file,file_num):
    logging.info("Reading Pre-processed CICIDS CSV_file...")
    df_CICIDS_csv=pd.read_csv(CICIDS_csv)
    df_CICIDS_csv=df_CICIDS_csv[['Timestamp','Source IP','Destination IP','Destination Port','Source Port','Protocol','Label']]
    df_CICIDS_csv.rename(columns={'Timestamp': 'stime', 'Source IP': 'srcip', 'Destination IP': 'dstip', 'Destination Port': 'dsport', 'Source Port': 'sport', 'Label': 'label','Protocol': 'protocol_m'}, inplace=True)
    
    df_CICIDS_csv['stime']=df_CICIDS_csv['stime'].apply(lambda x: (datetime.strptime(x, '%d/%m/%Y %H:%M')) if x.count(':') == 1 else  (datetime.strptime(x, '%d/%m/%Y %H:%M:%S')))
    df_CICIDS_csv['stime']=df_CICIDS_csv['stime'].apply(lambda x: int((datetime(x.year,x.month,x.day,(x.hour+12),x.minute,x.second)).timestamp()) if (x.hour>=1)&(x.hour<=7) else int((datetime(x.year,x.month,x.day,x.hour,x.minute,x.second)).timestamp()) )
    df_CICIDS_csv=df_CICIDS_csv.sort_values(by='stime')
    
    df_CICIDS_csv['protocol_m'] = df_CICIDS_csv['protocol_m'].astype(str)
    df_CICIDS_csv['protocol_m']=df_CICIDS_csv['protocol_m'].apply(lambda x: x.replace('6.0', 'tcp'))
    df_CICIDS_csv['protocol_m']=df_CICIDS_csv['protocol_m'].apply(lambda x: x.replace('17.0', 'udp'))
    df_CICIDS_csv['protocol_m']=df_CICIDS_csv['protocol_m'].apply(lambda x: x.replace('0.0', 'other'))
    
    for pcap_file in pcap_csv:
        logging.info("Reading Parsed_Pcap_file_%s ......",file_num)
        df_pcap_csv=pd.read_csv(pcap_file,index_col=0)
        df_pcap_csv=df_pcap_csv.sort_values(by='stime')
        
        stime=df_pcap_csv.stime[0]
        ltime=int(df_pcap_csv.stime.tail(1))
        df_pcap_csv.drop(columns=['frame_num','stime','ltime','protocol_s'],inplace=True)
        
        df_red=df_CICIDS_csv[(df_CICIDS_csv['stime']>=stime) & (df_CICIDS_csv['stime']<=ltime)]
        
        combine=df_pcap_csv.merge(df_red, left_on=['srcip','dstip','dsport','sport','protocol_m'], right_on=['srcip','dstip','dsport','sport','protocol_m'])
        combine.drop_duplicates(inplace=True)
        
        if file_num==2:
            combine.drop(combine[(combine.stime>=1499177940)&(combine.stime<=1499181660)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499194800)&(combine.stime<=1499198400)&(combine.label=='BENIGN')].index,inplace=True)
        elif file_num==3:
            combine.drop(combine[(combine.stime>=1499266020)&(combine.stime<=1499267400)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499267640)&(combine.stime<=1499268900)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499269380)&(combine.stime<=1499270400)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499271000)&(combine.stime<=1499271780)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499285520)&(combine.stime<=1499286720)&(combine.label=='BENIGN')].index,inplace=True)
        elif file_num==4:
            combine.drop(combine[(combine.stime>=1499371200)&(combine.stime<=1499373900)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499369400)&(combine.stime<=1499369700)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499355600)&(combine.stime<=1499355720)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499354100)&(combine.stime<=1499355300)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499350800)&(combine.stime<=1499353200)&(combine.label=='BENIGN')].index,inplace=True)
        elif file_num==5:
            combine.drop(combine[(combine.stime>=1499453700 )&(combine.stime<=1499459400)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499453700 )&(combine.stime<=1499459400)&(combine.label=='BENIGN')].index,inplace=True)
            combine.drop(combine[(combine.stime>=1499439720 )&(combine.stime<=1499443320)&(combine.label=='BENIGN')].index,inplace=True)
        
        print("*********Labelled_File_%s_Protocols*************"%file_num)
        print(combine.protocol_m.value_counts())
        print("************************************************")
        
        csv_out=output_file+"labelled_pcap_csv_"+str(file_num)+".csv"
        combine.to_csv(csv_out,index=False)
        file_num+=1


    
    