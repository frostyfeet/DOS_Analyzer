#!/usr/bin/python

###############################################################################
# Summary:  This scripts calculates some easy statistics to check if this is  #
#           a DDoS and what kind of DoS is.                                   #
# Creation date: 10-2014                                                      #
# Changelog:                                                                  #
#                                                                             #
# Author: Felipe Molina                                                 jJ
###############################################################################

import os,re
import commands
import socket
from optparse import OptionParser
from colorama import Fore,Back,Style,init
from collections import Counter

NTOP=20
init()

#lalalalal
def banner():
        print Fore.BLUE+"======================="
        print Fore.BLUE+"=== Is This a DDoS? ==="
        print Fore.BLUE+"======================="
        print Fore.BLUE+"* Print input and output stats of a targeted ip"
        print Fore.BLUE+"* Shows kind of DDoS"
        print Fore.BLUE+"* Shows top "+str(NTOP)+" IP participating in the traffic and % with total traffic"
        print Fore.BLUE+"* Shows top "+str(NTOP)+" source ports (amplification-spoofed source attacks) and % with total traffic" 
        print Fore.BLUE+"* Shows top "+str(NTOP)+" destination IPs and % with total traffic"
        print Fore.BLUE+"* Shows top "+str(NTOP)+" destination ports and % with total traffic"
        print Fore.BLUE+"* Shows percentage of protocol (TCP,UDP,ICMP) and % with total traffic"
        print Fore.RESET

def parseOptions():
        parser = OptionParser()

        parser.add_option("-f", "--file", dest="pcapfile",
                          help="Input PCAP File", metavar="FILE")
        parser.add_option("-o", "--output", dest="outfile",
                          help="write CSV report", metavar="FILE")
        parser.add_option("-t", "--target", dest="targetip",
                          help="targeted IP in the attack", metavar="string")
        # parser.add_option("-q", "--quiet",
        #                  action="store_false", dest="verbose", default=True,
        #                  help="don't print status messages to stdout")

        (options, args) = parser.parse_args()
        return options

def checkDependencies():
    tpaths=commands.getoutput("whereis -b tshark | cut -f2 -d':'")
    cpaths=commands.getoutput("whereis -b capinfos | cut -f2 -d':'")
    if tpaths is not None and cpaths is not None:
        if len(tpaths.strip()) > 0 and len(cpaths.strip())>0:
            return True
        else:
            return False

    else:
        return False

def getPCAPInfo(capfile):
    cinfoout=commands.getoutput("capinfos "+capfile)
    for line in cinfoout.split("\n"):
        print line

def getTopIPandPorts(pcapfile,targetip):
    ipsources=[]
    ipdestinations=[]
    portsources=[]
    portdestinations=[]

    if targetip is not None:
        tcmd="tshark -r "+pcapfile+" '!(ip.src == "+targetip+")' -E separator=';' -Tfields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport"

    else:
        tcmd="tshark -r "+pcapfile+" -E separator=';' -Tfields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport" 

    sourcesip=commands.getoutput(tcmd)
    for line in sourcesip.split("\n"):
        normline=line.split(";")
        ipsources.append(normline[0])
        portsources.append(normline[1])
        ipdestinations.append(normline[2])
        portdestinations.append(normline[3])

    cipsources = Counter(ipsources)
    cipdest = Counter(ipdestinations)
    cportsources = Counter(portsources)
    cportdest = Counter(portdestinations)

    return cipsources,cportsources,cipdest,cportdest

def getInputOutputRequests(pcapfile,targetip):
    itcmd="tshark -r "+pcapfile+" 'ip.dst == "+targetip+"' -Tfields -e ip.src | wc -l" 
    otcmd="tshark -r "+pcapfile+" 'ip.src == "+targetip+"' -Tfields -e ip.dst | wc -l" 
    nrequests=int(commands.getoutput(itcmd))
    nresponses=int(commands.getoutput(otcmd))
    
    return nrequests,nresponses


#######e
# MAIN #
########

banner()
op=parseOptions()

if checkDependencies():
    print "Getting general information about the pcap..."
    # getPCAPInfo(op.pcapfile)
    
    #####################
    # Top IPs and Ports #
    #####################
    print "Getting the list of top "+str(NTOP)+" source IP"
    cipsrc,cportsrc,cipdst,cportdst=getTopIPandPorts(op.pcapfile,op.targetip)
    nsrcips=len(cipsrc.keys())
    ndstips=len(cipdst.keys())
    nsrcports=len(cportsrc.keys())
    ndstports=len(cportdst.keys())

    print "================================================="
    print "N of unique source IPs: %s" % nsrcips
    print "N of unique destination IPs: %s" % ndstips
    print "N of unique source ports: %s" % nsrcports
    print "N of unique destination ports: %s" % ndstports
    print "N of total sources IP occurrences: %s" % sum(cipsrc.values())
    print "N of total destination IP occurrences: %s" % sum(cipdst.values())
    print "N of total sources ports occurrences: %s" % sum(cportsrc.values())
    print "N of total destination ports occurrences: %s" % sum(cportdst.values())
    print "================================================="


    print "Top "+str(NTOP)+" source IPs"
    for topsrc in cipsrc.most_common(NTOP):
        # hostname=socket.gethostbyaddr(topsrc[0])
        print "- "+topsrc[0]+": "+str(topsrc[1])+" ("+str(round((float(topsrc[1])/sum(cipsrc.values()))*100,2))+"% of src occurrences)"
    print "Top "+str(NTOP)+" destination IPs of "+str(ndstips)+": "
    for topdst in cipdst.most_common(NTOP):
        # hostname=socket.gethostbyaddr(topdst[0])
        print "- "+topdst[0]+": "+str(topdst[1])+" ("+str(round((float(topdst[1])/sum(cipdst.values()))*100,2))+"% of dst occurences)"
    print "Top "+str(NTOP)+" source ports of "+str(nsrcports)+": "
    for topsrc in cportsrc.most_common(NTOP):
        print "- "+topsrc[0]+": "+str(topsrc[1])+" ("+str(round((float(topsrc[1])/sum(cportsrc.values()))*100,2))+"% of src port occurences)"
    print "Top "+str(NTOP)+" destination ports of "+str(ndstports)+": "
    for topdst in cportdst.most_common(NTOP):
        print "- "+topdst[0]+": "+str(topdst[1])+" ("+str(round((float(topdst[1])/sum(cportdst.values()))*100,2))+"% of dst port occurences)"
    
    ########################################
    # Input packets against output packets #
    ########################################
    # Calculate input traffic against output traffic for target ip
    print "Calculating Input/Output ratio..."
    if op.targetip is not None:
        nreq,nresp=getInputOutputRequests(op.pcapfile,op.targetip)
        ratio=round((float(nreq)/nresp)*100,2)
        print "I/O Ratio of "+op.targetip+": %s%% (%s requests/%s responses)" % (ratio,nreq,nresp)
        print "(The greater this ratio is, the more input is receiving the targeted IP against its responses)"
    else:
        print "No target IP was defined. Skipping I/O ration test"

    
    # Calculate medium and deviation of packets per seconds.
    # getMediumAndDevPackPerSec(pcapfile)
    # volumetry or N of Packets each framelen seconds. To do a nice bar graph
    # volumetry=getVolumetry(framelen)
    # print volumetry
    # saveVolumetryToCSV(volumetry)
    # Check blacklists and whois for the top common ips
else:
    print "Needed programs were not found in your PATH. Please check that 'tshark' and 'capinfos' are available"
    exit(0)
