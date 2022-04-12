# Watcher
A network monitoring tool written in python.

This program uses three very rudimentary parameters for detecting "suspicious" network activity.
1. Captured packets' source and destination addresses are compared to a list of authorized IPs.
2. The source and destination addresses are also compared to a list of devices that should not be communicating with each other. If both the source and the destination are found, an alert will be triggered and the packet logged.
3. The TCP flags of each packet are examined and a count of the SYN and ACK flags for each round of captured packets is made. If there are more SYN flags than ACK flags, an alert is triggered.
