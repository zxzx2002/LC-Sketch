# LC-Sketch
Source code for LC-Sketch (ICASSP 2026)
## Paper
LC-Sketch: A Layered-Carry Sketch for IoT Network Measurement
## Cite
https://doi.org/10.1109/ICASSP55912.2026.11462486 (ICASSP 2026)
## Abstract
Network measurement (NM) plays a vital role in enhancing the security of Internet of Things (IoT) network by enabling fine-grained flow analysis and real-time anomaly detection. With the advancement of programmable network, sketch-based methods have been deployed in the data plane to achieve line-rate NM. However, existing sketches face challenges in resource efficiency and measurement accuracy under high-volume traffic from diverse sources in the IoT network. To address this issue, we propose the LC sketch for resource-efficient and accuracy-reliable IoT NM. Specifically, for resource efficiency, the LC sketch employs a layered carry mechanism to reduce sketch counter sizes. For reliable accuracy, a hot-cold bucket strategy with a locking mechanism protects large flow measurement from hash collisions. Additionally, we introduce an optimal sketch parameter deployment algorithm to balance resource cost and NM accuracy. We implement the LC sketch on an Intel Tofino2 switch. Experimental results indicate that the LC sketch achieves resource-efficient and accuracy-reliable IoT NM.
## Source Code Usage
### Overview
We have provided three folders with the same structure.
#### LC_Sketch_zx/
It contains P4 programs for our proposed LC-Sketch, which is written by Xun Zhou. The main program is the "LC-Sketch.p4", and related "header.p4" (i.e., defining the P4 headers) and "parser.p4" (i.e., defining the P4 parser process) are provided in the "include/" folder. 
#### HLL_CM_zxc/
It contains P4 programs for the HLL-CM Sketch, which is written by Xinchang Zhou. The main program is the "hllcm.p4", and related "header.p4" (i.e., defining the P4 headers) and "parser.p4" (i.e., defining the P4 parser process) are provided in the "include/" folder. 
#### LTC_wyk/
It contains P4 programs for the LTC Sketch, which is written by Yike Wang. The main program is the "ltcsketch.p4", and related "header.p4" (i.e., defining the P4 headers) and "parser.p4" (i.e., defining the P4 parser process) are provided in the "include/" folder. 
### Setup Instructions
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.
