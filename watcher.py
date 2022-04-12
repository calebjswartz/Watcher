import pyshark
import time

INTERVAL = 30 # interval for wait function
IFACE_NAME = "en0" # set capture interface
NETWORK_ADDRESSES = ['192.168.1.28'] # authorized addresses go here
COM_BLACKLIST = [] # list ip addresses for devices that should not communicate here
count = 0 # global counter for wait function to track how many times capture has run

def wait():
    time.sleep(INTERVAL)
    if count > 10:
        count = 0
    else:
        count = count + 1
    capture()
        

def capture():
    cap = pyshark.LiveCapture(interface=IFACE_NAME)
    cap.sniff(timeout=10, packet_count=10)
    SYN = 0 # store SYN count
    ACK = 0 # store ACK count
    for packet in cap: # loop through capture
        if hasattr(packet, 'ip'): #check for ip packets
            source_address = str(packet.ip.src)
            destination_address = str(packet.ip.dst)
            for address in NETWORK_ADDRESSES: # make sure traffic is from approved addresses
                if source_address != address and destination_address != address:
                    print("Unauthorized IP address detected!")
                    log(packet)
                    print("Destination: " + destination_address)
                    print("Source: " + source_address)
            for address in COM_BLACKLIST: # check for suspicious communications
                if source_address in COM_BLACKLIST and destination_address in COM_BLACKLIST:
                    print("Suspicious communication detected!")
                    log(packet)
        if hasattr(packet, 'tcp'): # check TCP flags
            flag = packet.tcp.flags
            flag = str(flag)
            if flag == "0x0002":
                SYN +=1
            if flag == "0x0010":
                ACK +=1
        if SYN > ACK: # check for SYN scan/SYN flood
            print("SYN scan detected!")
            log(packet)
    wait()

def log(packet):
    with open("log.txt", 'a') as file:
        file.write(str(packet))
        file.write("\n")
        file.close()

#start the monitoring process
while True:
    try:
        capture()
    except:
        wait()