# pcap_scan
smart filter for PCAP files, for Telecom purposes.

to compile:
gcc pcap.c cond.c pcap_read.c -o pcap_read

Version 0.98.4
pcap_scan  -o <outfile> -i <infile> [-i] <infile> .. -cX <value> [-cX <value>]...[-cX <value>]  
Mandatory:
 -o <outfile>			PCAP file with matched packets
 -i <infile> [<infile>]...	one or more PCAP files to read. Gzip is supported. Note, bash automatically resolve mask to list.
Conditions: (if no conditions specified, take ALL packets with SIP, DIAMETER, MAP, CAP)
 -ci <imsi>
 -cm <msisdn>
 -cg <global title>
 -ct <tid>			(example: a1B2c3D4)
 -tp <tid1>:<tid2>
 -cc <SIP Call-ID>
 -cd <DIAMETER Session-Id>
 -cf <input file with conditions>
Options
 -v1  				don't skip VLAN packets
 -r <output file with conditions>
 -a1 				append outfile (if exist) (when -cf specified, -a1 assumed as default)
 -a0 				overwrite outfile
 -w 				scan input files two times (useful for files from STP pair, for example)
learn mode (default is -l2)
 -l0 				don't expand condition list during scan
 -l1 				expand condition list during scan only with tid, SessionID, CallID
 -l2 				expand condition list during scan with tid, SessionID, CallID, IMSI, MSISDN called and calling
 -D <debug_key>
