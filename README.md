# pcap_scan
smart filter for PCAP files, for Telecom purposes.

to compile:
gcc pcap.c cond.c pcap_read.c -o pcap_read

<pre>
Version 0.98.4
pcap_scan  -o &ltoutfile&gt -i &ltinfile&gt [-i] &ltinfile&gt .. -cX &ltvalue&gt [-cX &ltvalue&gt]...[-cX &ltvalue&gt]  
Mandatory:
 -o &ltoutfile&gt			PCAP file with matched packets
 -i &ltinfile&gt [&ltinfile&gt]...	one or more PCAP files to read. Gzip is supported. Note, bash automatically resolve mask to list.
Conditions: (if no conditions specified, take ALL packets with SIP, DIAMETER, MAP, CAP)
 -ci &ltimsi&gt
 -cm &ltmsisdn&gt
 -cg &ltglobal title&gt
 -ct &lttid&gt			(example: a1B2c3D4)
 -tp &lttid1&gt:&lttid2&gt
 -cc &ltSIP Call-ID&gt
 -cd &ltDIAMETER Session-Id&gt
 -cf &ltinput file with conditions&gt
Options
 -v1  				don't skip VLAN packets
 -r &ltoutput file with conditions>
 -a1 				append outfile (if exist) (when -cf specified, -a1 assumed as default)
 -a0 				overwrite outfile
 -w 				scan input files two times (useful for files from STP pair, for example)
learn mode (default is -l2)
 -l0 				don't expand condition list during scan
 -l1 				expand condition list during scan only with tid, SessionID, CallID
 -l2 				expand condition list during scan with tid, SessionID, CallID, IMSI, MSISDN called and calling
 -D &ltdebug_key&gt
</pre>
