# Network Anomaly Detector

## Overview
This repository contains a project which can detect network anomalies from the packets sent to and from a specific system. It takes a `.pcap` file as an input, and generates a `.csv` report with 3 columns: Source IP, timestamp and column which signifies whether an anomaly was detected at that time and from that IP (1 for anomaly detected, 0 for not detected). There is a minimal UI to run this as well, usage outlined below.
## Metrics
The metrics we obtained during testing of the ML models is
```
Accuracy: 99.6%
Precision: 98.8%
Recall: 99.0%
F1 score: 98.9%
```
For more information, refer to the notebooks in `network-anomaly-detection/models/`.
## Usage
### Installation
```bash
git clone https://github.com/KapilM26/license-plate-reader.git
cd network-anomaly-detection
pip3 install -r requirements.txt
```
### Running the server
```
cd network_intrusion
python manage.py runserver
```
This will start a local server on http://127.0.0.1:8000/. There is a minimal UI where you can upload a pcap file and get an output report. An example pcap file can be found in `network_intrusion/intrusion/media`.