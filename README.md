A. Packages required :

1. numpy
2. sklearn
3. pandas
4. lightgbm
5. os
6.sys
7. csv
8. scapy

B. How to install packages :

	From Terminal : $ pip install <package name>

C. This folder contains a python program "botnetdetect.py"
   This program takes an input as .pcap file and outputs in format

	Flow= (srcAddr, sPort, dstAddr, dPort, Protocol)	Prediction
		<Flow-5-Tuple>					malicious/benign
