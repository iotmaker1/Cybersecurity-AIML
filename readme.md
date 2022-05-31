# Cybersecurity use cases for AIML

## Projects

### Machine learning for linux syslog 

#### Use case
<strong> Linux Syslog machine learning using Weka </strong>

This project is associated with prediction of cybersecurtiy attacks on linux based systems that use syslog and have services writing logs to syslog. The initial data normalization covers aspects of analyzing the log structure to extract various fields to classify events and os operations in raw log data. The initial normalization step just creates a data model and dimensions of various operating system events and operations.

This data model is then used for further calssifying the os operations and events for building a basline. To this baseline attack data patterns are added to train the model of what an attack would look like. An iterative learning run would then be able to classify and predict type of attack based on the pattern seen. In subsequent   phases additonal attack data with different services like SSH, FTP, RPC-NFS etc. are run against the data to analyze the predictability.

As the machine learning picks up these patterns it can predict a possibility of an attack progression based on services running on a linux system. It can then provide a risk assessment report with possible recommendations. The data used for this experimental project was obtained from [logpai loghub repository](https://github.com/logpai/loghub).

In the example project that was carried out as part of IA645 Machine Learning for Cybersecurity at Eastern Michigan University, the team of four students worked on this project with guidance from faculty.

Team members:
- Professor Dr Omar Darwish
- Aaron Liske (Lead)
- William Smith III
- Mia Jones
- Yogesh Chavarkar
 


#### Details

Four distinct attack patterns were used from the sample files from the [logpai loghub repository](https://github.com/logpai/loghub) repository.

- Brute Force Attacks
- FTP Brute force and Denial of Service
- NFS Buffer flow through RPC
- Clearning of system logs

Event patterns were grouped based on time, users and service to classify the attacks. Preview of the data was perfromed in Azure log analytics. Custom tables were used to ingest syslog text rawlog data from a linux VM.  Custom field extractions were used to extract fields from text files into 4 parts to analyze data.

- Time
- host
- service
- message

List of files:
 - Linux-logs: This folder contains the raw syslog files.
 - sample.csv: Data was extracted in this file for review by professor and get approval to proceed with other tools and steps.
 - log_etl.py: Python code that parses the syslog data and classifies it based on the time, service, user and attack activity reported.
 - data.csv: classified csv file that contains the classifications and the raw data.
 - WEKA-Dataset.csv: classified file that contains only the classifications to be used for Weka processing without the raw data field.
