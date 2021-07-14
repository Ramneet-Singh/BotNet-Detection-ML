# Machine Learning based P2P Bot-Net Detection through Network Flow Analysis

This repository contains Team SaRaNi's (with me as **Team Leader**) submission to the **HCL Hack IITK 2020 Cybersecurity Hackathon**. We won the **Third Prize** globally for developing this tool. Note that the actual submission contained some preprocessed data as well, which is way too large to upload. We have included our **Finals Presentation**, please check it out for a summary of our contributions as well as future directions to improve this tool.

## Index
- [**Motivation**](#motivation)
- [**Machine Learning Pipeline**](#machine-learning-pipeline)
    1. [**Feature Extraction**](#1-feature-extraction)
    2. [**Feature Selection**](#2-feature-selection)
    3. [**Model Building**](#3-model-building)
    4. [**Model Testing**](#4-model-testing)
- [**Unique Contributions**](#unique-contributions)
- [**Execution Instructions**](#execution-instructions)

## Motivation

A bot-net is a network of infected hosts (bots) that works independently under the control of a Botmaster (Bot herder), which issues commands to bots using command and control (C&C) servers. Traditionally, bot-nets used a centralized client-server architecture which had a single point of failure but with the advent of peer-to-peer technology, the problem of single point of failure seems to have been resolved. Gaining advantage of the decentralized nature of the P2P architecture, botmasters started using P2P based communication mechanism. P2P bot-nets are **highly resilient** against detection even after some bots are identified or taken down. P2P bot-nets provide central frameworks for different cyber-crimes which include DDoS (Distributed Denial of Service), email spam, phishing, password sniffing, etc.  

The objective was to develop a tool for **identifying P2P bot-nets using network traffic analysis**. We also detect the hosts involved in P2P traffic and then the detected hosts are further analyzed to detect bot-nets. We formulated the underlying problem as a **Classification** problem, which was given as input a Flow, which is a 5-Tuple of (srcAddr, sPort, dstAddr, dPort, Protocol), and had to output a label classifying the flow as malicious or benign. The overall tool then, took as input a .pcap file which captured the traffic over a network, parsed the file to identify flows, and then used our trained model to classify each flow on-the-fly as malware/benign. Below we give a brief overview of our machine learning pipeline.

## Machine Learning Pipeline

### 1. Feature Extraction

- We manually tested examined the data, for getting a comprehensive understanding of the dataset provided.
- We consulted multiple research papers to get an understanding of the different methods that we could use to approach the problem and create an exhaustive set of features.
- Raw data files were parsed and the previously decided features were extracted.
- We had a dataset with 2.57 Million examples in total, which we then split into Train, Validation and Test Sets (the sizes are mentioned in subsequent steps).


### 2. Feature Selection

- We ran 2 Feature Selection algorithms on the train set, namely **Select-K-Best** and **Recursive Feature Elimination (RFE)**.
- Through the results from these two, we selected the 10 best features out of 23 initial features that we had identified.

### 3. Model Building

- We used a Gradient Boosting Decision Tree framework called LightGBM, which is efficient and capable of handling large-scale data.
- We tuned the Hyperparameters like max_depth to make our model robust and prevent overfitting.
- The Cross-Validation Set Size was 33.33% of our training set.
- Cross-Validation Accuracy was used as the evaluation metric.
- Batch-learning was used with a Batch-size of 10000.

### 4. Model Testing

- We tested the model with 10% of our total data.
- Some of the results that we obtained are:  

Accuracy | Precision | Recall | F1 Score
---------|-----------|--------|---------
99.90%   | 99.93%    | 99.95% | 99.94%
	
## Unique Contributions

- All the research papers we consulted used a subset of possible features for classification. We combined all of them to create an **exhaustive** feature set, and then selected the best out of them.
- Most papers only used direct flow-based features. However, we also **hand-engineered certain statistical features**, which we intuitively felt could be useful for classification after manual inspection of sample files.
- The majority of previous approaches were aimed at detecting General Botnets. We focused on **P2P Botnets only**, and did not consider features pertaining to IRC Botnets. 
- Past work that we saw either used basic ML Algorithms like Naive Bayes and Random Forest or computation intensive methods like Neural Networks. We used the **Fast and Sophisticated LightGBM** model, based on Gradient Boosted Decision Trees. This not only **reduced the Training Time**, but also **increased Accuracy**.

## Execution Instructions

1. Packages required :
	1. numpy
	2. sklearn
	3. pandas
	4. lightgbm
	5. os
	6.vsys
	7. csv
	8. scapy

2. How to install packages :  
	From Terminal : ```$ pip install <package name>```

3. This folder contains a python program "botnetdetect.py". This program takes as command line input (path to) a .pcap file and outputs in the format  

Flow= (srcAddr, sPort, dstAddr, dPort, Protocol) |	Prediction
------------------------------------------------|------------------
  \<Flow-5-Tuple\>				|	malicious/benign
