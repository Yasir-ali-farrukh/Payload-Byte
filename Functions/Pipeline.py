from Functions.Optimized_Parser_Labelling import *
import os
import pandas as pd
import numpy as np
from datetime import datetime


def pipeline(in_dir,out_dir,dataset,processed_csv_file):
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s -%(message)s')
    if dataset=='UNSW':
        logging.info("Checking directory for files ......")
        check=os.path.exists(in_dir+"/pcap 22-1-2015/1.pcap")
        if not check:
            print("Pcap Files not Found in the current folder. Please Enter Correct Directory")
        else:
            logging.info("Files found. Initiating PCAP Parsing.......")
            pcap_file_list=[]
            pcap_jan=in_dir+"/pcap 22-1-2015/"
            for x in range(1,54): ## 22-1-2015 have 53 pcap files
                pcap_file_list.append(pcap_jan+str(x)+".pcap")
            out_file=out_dir+"/pcap_file_csv_parser/22-1-1015/"
            isExist=os.path.exists(out_file)
            if not isExist:
                os.makedirs(out_file)
            logging.info("Parsing 22-1-2015 Files .........")
            pcap_parser(pcap_file_list,out_file,1)
            
            
            logging.info("Parsing 17-2-2015 Files .........")
            pcap_file_list=[]
            pcap_feb=in_dir+"/pcap 17-2-2015/"
            for x in range(1,28): ## 17-2-2015 have 27 pcap files
                pcap_file_list.append(pcap_feb+str(x)+".pcap")
            out_file=out_dir+"/pcap_file_csv_parser/17-2-1015/"
            isExist=os.path.exists(out_file)
            if not isExist:
                os.makedirs(out_file)
            pcap_parser(pcap_file_list,out_file,1)
            
            logging.info("Parsing Completed.......")

            ### Labeling 17-2-2015
            pcap_csv=[]
            for x in range(1,28): ## 17-2-2015 have 27 pcap files
                pcap_csv.append(out_file+"pcap_csv_"+str(x)+".csv")
            logging.info("Labeling 17-2-2015 Files .........")
            output_file=out_dir+"/Labelled_pcap_file/17-2-1015/"
            isExist=os.path.exists(output_file)
            if not isExist:
                os.makedirs(output_file)
            label(pcap_csv,processed_csv_file,output_file,1)
            
            ### Labeling 22-1-2015
            out_file=out_dir+"/pcap_file_csv_parser/22-1-1015/"
            pcap_csv=[]
            for x in range(1,54): ## 22-1-2015 have 53 pcap files
                pcap_csv.append(out_file+"pcap_csv_"+str(x)+".csv")
            logging.info("Labeling 22-1-2015 Files .............")
            output_file=out_dir+"/Labelled_pcap_file/22-1-1015/"
            isExist=os.path.exists(output_file)
            if not isExist:
                os.makedirs(output_file)
            label(pcap_csv,processed_csv_file,output_file,1)
            
            logging.info("Labeling Completed .......; Initiating Combining and Processing of Labeled Files")
            
            a=[]
            for x in range(1,2): ## 22-1-2015 have 53 pcap files
                a.append(output_file+"labelled_pcap_csv_"+str(x)+".csv")
                
            in_file=[]
            output_file=out_dir+"/Labelled_pcap_file/17-2-1015/"
            for x in range(1,2): ## 17-2-2015 have 27 pcap files
                in_file.append(output_file+"labelled_pcap_csv_"+str(x)+".csv")
            in_file=in_file+a
            out_path=out_dir+"/Labelled_pcap_file/"
            logging.info("Combining all Files ........")
            df_payload=combine(in_file,out_path)
            
            logging.info("Total Shape of Combined Data Before Processing is: %s",df_payload.shape)
            logging.info("Removing Duplicates ......")
            df_payload.drop_duplicates(inplace=True)
            
            logging.info("Removing Non-Payload Data Instances .........")
            df_payload.drop(df_payload[df_payload.payload.isnull()].index,inplace=True)
            df_payload['payload_int'] = df_payload['payload'].apply(int, base=16)
            df_payload.drop(df_payload[df_payload.payload_int==0].index,inplace=True)
            df_payload.pop('payload_int')
            
            df_payload.sort_values(by=['stime','frame_num'],inplace=True,ignore_index=True)
            df_payload.sttl=df_payload.sttl.astype('int32')
            df_payload.dsport=df_payload.dsport.astype('int32')
            df_payload.sport=df_payload.sport.astype('int32')
            df_payload.total_len=df_payload.total_len.astype('int32')
            df_payload.pop('frame_num')
            df_payload.pop('stime')
            df_payload.pop('protocol_s')
            df_payload.pop('proto')
            df_payload.pop('dur')
            df_payload.pop('label')
            
            final_out=out_dir+"/Labelled_pcap_file/Final_Labeled_and_processed/"
            isExist=os.path.exists(final_out)
            if not isExist:
                os.makedirs(final_out)  
            final=final_out+"combined_labelled_cleaned_sorted_pcap_csv.csv"
            logging.info("Exporting Finalized Version of Data .............")
            df_payload.to_csv(final,index=False)
            
            logging.info("Process Completed ...................")
            return df_payload
              
            
    elif dataset=="CICIDS":
        logging.info("Checking directory for files ......")
        check=os.path.exists(in_dir+"/Monday-WorkingHours.pcap")
        if not check:
            print("Pcap Files not Found in the current folder. Please Enter Correct Directory")
        else:
            logging.info("Files found. Initiating PCAP Parsing.......")
            pcap_file_list=[]
            days=['Monday','Tuesday','Wednesday','Thursday','Friday']
            for x in days:
                pcap_file_list.append(in_dir+"/"+x+"-WorkingHours.pcap")
            out_file=out_dir+"/pcap_file_csv_parser/"
            isExist=os.path.exists(out_file)
            if not isExist:
                os.makedirs(out_file)
            logging.info("Parsing PCAP Files .........")
            pcap_parser(pcap_file_list,out_file,1)
            logging.info("Parsing Completed.......")
            ## Labeling 
            
            pcap_csv=[]
            for x in range(1,6): ## Five days files 
                pcap_csv.append(out_file+"pcap_csv_"+str(x)+".csv")
            logging.info("Labeling PCAP Files .........")
            output_file=out_dir+"/Labelled_pcap_file/"
            isExist=os.path.exists(output_file)
            if not isExist:
                os.makedirs(output_file)
            label_CICIDS(pcap_csv,processed_csv_file,output_file,1)
    
            logging.info("Labeling Completed .......; Initiating Combining and Processing of Labeled Files")
            
    
            in_file=[]
            for x in range(1,6): ## Hve 5 days pcap files
                in_file.append(output_file+"labelled_pcap_csv_"+str(x)+".csv")
            
            logging.info("Combining all Files ........")
            df_payload=combine_CICIDS(in_file,output_file)
            
            logging.info("Total Shape of Combined Data Before Processing is: %s",df_payload.shape)
            logging.info("Removing Non-Payload Data Instances .........")
            df_payload.drop(df_payload[df_payload.payload.isnull()].index,inplace=True)
            x=df_payload['payload']
            new=[]
            for p in range(len(x)):
                o=(int((x.iloc[p]), 16))
                if o>0:
                    new.append(1)
                else:
                    new.append(0)
                    
            df_payload['payload_int']=new
            
            df_payload.drop(df_payload[df_payload.payload_int==0].index,inplace=True)
            df_payload.pop('payload_int')
            
            df_payload.sttl=df_payload.sttl.astype('int32')
            df_payload.dsport=df_payload.dsport.astype('int32')
            df_payload.sport=df_payload.sport.astype('int32')
            df_payload.total_len=df_payload.total_len.astype('int32')
            logging.info("Total Shape of Combined Data After Processing is: %s",df_payload.shape)
            final_out=out_dir+"/Labelled_pcap_file/Final_Labeled_and_processed/"
            isExist=os.path.exists(final_out)
            if not isExist:
                os.makedirs(final_out)
            
            df_payload.rename(columns = {'label':'attack_cat'}, inplace = True)
            final=final_out+"combined_labelled_cleaned_sorted_pcap_csv.csv"
            logging.info("Exporting Finalized Version of Data .............")
            df_payload.to_csv(final,index=False)
            logging.info("Process Completed ...................")
            return df_payload
            
    else:
        print("Wrong Input for Dataset. Kindly Chose from UNSW or CICIDS")
        
##################################################################################        
        
""" Function: Covert Labelled Pcap file's payload data(hex) into byte (int) 
    Input: Labelled Pcap file Data in panda Dataframe
    Output: X ---> Payload data in int form in range of 0-255 in 1500 Columns
            Y ---> Attack Category for each data                          """        

def payload_to_bytes(df,dim):
#     indexes = np.arange(len(df.index))
    df_temp = df
    X = df_temp['payload'].to_numpy().reshape((-1, 1))
    X = np.apply_along_axis(payload_transform, 1, X, dim)
    y = np.array(df_temp['label']).reshape((-1, 1))
    return X, y

def payload_transform(x, dims):
    byte_array = bytes.fromhex(x[0])
    byte_lst = list(byte_array)
    if (len(byte_lst) < dims):
        output = np.pad(byte_lst, (0, dims-len(byte_lst)), 'constant')
    else:
        output = np.array(byte_lst[0:dims].copy())
    output = np.abs(output.astype('int32'))
    #output = np.abs(output.astype(float)) / 255
    #return output.astype(float)
    return output


##################################################################################

def transform(df,out_dir):
    le = LabelEncoder()
    df['protocol_m']=le.fit_transform(df['protocol_m'])
    X_tr,Ytrain =payload_to_bytes(df,1500)
    X_tr = np.column_stack((X_tr,np.array(df.iloc[:,5])))
    X_tr = np.column_stack((X_tr,np.array(df.iloc[:,6])))
    X_tr = np.column_stack((X_tr,np.array(df.iloc[:,4])))
    X_tr = np.column_stack((X_tr,np.array(df.iloc[:,8])))
    name=[]
    for x in range(1,1501):
        name.append("payload_byte_"+str(x))
    name.append("ttl")
    name.append("total_len")
    name.append("protocol")
    name.append("t_delta")
    final = pd.DataFrame(X_tr, columns=name)
    final['label']=Ytrain
    final.to_csv(out_dir+"Converted_data.csv",index=False)
    return final
    
      
