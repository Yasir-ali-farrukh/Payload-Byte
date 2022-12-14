## Usage

Processed and labeled data of the following datasets can be accessed using the following links:

1. [UNSW-NB15](https://drive.google.com/drive/folders/1xuPB6VxQD70qvSH1YU69E2ICzLHJI2mO?usp=sharing)
2. [CIC-IDS2017](https://drive.google.com/drive/folders/1sFBgQyvO2Wde8fwgZXTgVFXrD2W7v8WB?usp=sharing)

Both of the datasets are in `.CSV` format. For attaining the complete data before processing and transformation, follows the given instruction for using Payload-Byte. 

## Dataset Struture
<p align="justify"> Available datasets comprise data from the packet header and packet data. Four features are extracted from packet header whereas payload data from packet data is presented in the byte-wise form. Payload data is transformed from hex values to integers on the basis of per byte. Therefore, each byte value ranges from 0-255.. Moreover, following the de facto packet size limit of 1500 bytes, we have limited the payload bytes to 1500. A representation of the feature vector of the available dataset is shown below: </p>


![image](/Data/Feature_Vector.png)
