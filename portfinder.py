#! /usr/bin/env python3
#SHEBANG
#Save file as <title>.py in your preferred location. Then start typing
#port scanner
import argparse
from scapy.all import *
import socket
from time import sleep
from loguru import logger
import pyfiglet

def banner():
    ascii_banner = pyfiglet.figlet_format("PORT FINDER")
    print(ascii_banner)

#argparse with description
def args():
    global target
    target = input("Please enter IP Address(8.8.8.8,..):")
    global port
    port = input("Please Specify ports (53 80 ...)(optional):")
    global scan
    scan = input("Please enter Scan type, TCP-Ack,TCP-Syn and UDP:")

#TCP-Sync     
def syn():
    print("TCP sync is choosen")   
    packet = IP(dst=target)/TCP(flags='S',dport=ports)
    answer,unanswer = sr(packet,timeout=3)
    answer.nsummary( lfilter=lambda s,r: (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )
    for r,s in answer:
        print(f"The source IP is {r[IP].src}")
    for sent,received in answer:
        print(f"Scanning port for {target}")
        print(f"The TCP port used to send is {sent[TCP].dport}")
        print(f"The TCP port used to receive is {received[TCP].sport}")
        if sent[TCP].dport == received[TCP].sport:
            print("Sent and received ports are matching")
#TCP-Async
def asyn():
    print("TCP async is choosen")
    packet = IP(dst=target)/TCP(flags='A',dport=ports)
    answer,unanswer = sr(packet,timeout=3)
    answer.nsummary( lfilter=lambda s,r: (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )
    for r,s in answer:
        print(f"The source IP is {r[IP].src}")
    for sent,received in answer:
        print(f"Scanning port for {target}")
        print(f"The TCP port used to send is {sent[TCP].dport}")
        print(f"The TCP port used to receive is {received[TCP].sport}")
        if sent[TCP].dport == received[TCP].sport:
            print("Sent and received ports are matching")
#UDP
def udp_scan():
    print("UDP is choosen")
    packet = IP(dst=target)/UDP(sport=RandShort(), dport=ports)/DNS(rd=1,qd=DNSQR(qname="google.com",qtype="MX"))
    answer,unanswer = sr(packet,timeout=3)
    answer.summary( lambda s,r : r.sprintf("%IP.src% is alive") )
    for r,s in answer:
        print(f"The source IP is {r[IP].src}")
    for sent,received in answer:
        print(f"Scanning port for {target}")
        print(f"The UDP port used to send is {sent[UDP].dport}")
        print(f"The UDP port used to receive is {received[UDP].sport}")
        if sent[UDP].dport == received[UDP].sport:
            print("Sent and received ports are matching")


def dikupaportscanner():
#write your main function here 
       try:
              banner()
              args()
              global ports
              if port:
                  ports = port
              else:
                # default port range
                  ports = range(1, 1024)
              scan.lower()
              if scan == "udp":
                  udp_scan()
              if scan == "tcp-ack":
                  syn()
              if scan == "tcp-syn":
                  asyn()

              logger.info("Press 'ctrl+c' to exit");sleep(2);
                     
       except KeyboardInterrupt:
              print("Exiting because of program interpreted by user"); print("Thanks for using my application");       
              
if __name__=='__main__':
       dikupaportscanner() 
#Program created by Dinesh_Kumar_Palanivelu 
