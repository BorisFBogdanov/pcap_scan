/* 
  cap-list
  Boris Bogdanov (c) 2017

*/
// todo: more boundary check in packets size
// todo: statitics

#define PCAP_SCAN_VERSION 0.98.4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gsm.h"
#include "pcap.h"
#include "cond.h"
//#define DEBUG


#define ST_STEP 1000
#define ST_INITIAL 3000


int process_file(const char *filename, FILE* outfile, TConditionsList * CList);

struct  {char *outfilename; char *condfilename; TConditionsList *Infiles; TConditionsList *Conditions; int VLAN; int append; int scan_counter; int scan_limit; int learn;} Config;
int packets_written;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
/*  BEGIN                                                    */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int main(int argc, char **argv){
const char *filename;
FILE *outfile, *condfile, *incondfile;
Condition *Infile;
int fc, i, j, diff;
int stop, pkt_counter;
unsigned int tid, ptid[2];
struct timeval time_stop, time_start, time_diff;
const char *help_banner = 
"Version 0.98.4\npcap_scan  -o <outfile> -i <infile> [-i] <infile> .. -cX <value> [-cX <value>]...[-cX <value>]  \nMandatory:\n -o <outfile>			PCAP file with matched packets\n -i <infile> [<infile>]...	one or more PCAP files to read. Gzip is supported. Note, bash automatically resolve mask to list.\nConditions: (if no conditions specified, take ALL packets with SIP, DIAMETER, MAP, CAP)\n -ci <imsi>\n -cm <msisdn>\n -cg <global title>\n -ct <tid>			(example: a1B2c3D4)\n -tp <tid1>:<tid2>\n -cc <SIP Call-ID>\n -cd <DIAMETER Session-Id>\n -cf <input file with conditions>\nOptions\n -v1  				don't skip VLAN packets\n -r <output file with conditions>\n -a1 				append outfile (if exist) (when -cf specified, -a1 assumed as default)\n -a0 				overwrite outfile\n -w 				scan input files two times (useful for files from STP pair, for example)\nlearn mode (default is -l2)\n -l0 				don't expand condition list during scan\n -l1 				expand condition list during scan only with tid, SessionID, CallID\n -l2 				expand condition list during scan with tid, SessionID, CallID, IMSI, MSISDN called and calling\n -D <debug_key>\n";

gettimeofday(&time_start, NULL);

//setbuf(stdout, NULL);
PCAP_DEBUG = pcap_dbg_file + pcap_dbg_tcap + pcap_dbg_bytes +  pcap_dbg_pkt + pcap_dbg_map + pcap_dbg_print;
PCAP_DEBUG = 0;

// config defaults
Config.Infiles 	  = init_ConditionsList();
Config.Conditions = init_ConditionsList();
Config.outfilename  = NULL;
Config.condfilename = NULL;
Config.append  	  = 0;
Config.learn      = 2;
Config.scan_limit = 1;
Config.VLAN	  = 0;

stop = 0;

pkt_counter = 0;
packets_written = 0;

if (sizeof(int) != 4) {printf("\nFatal: sizeof(int) not equal 4! change compiler settings!"); exit(0);}
if (argc < 2) { printf("%s",help_banner);  return(0);};

for(i = 1; i < argc; i++){
	switch (argv[i][0]){
		case '-':  switch(argv[i][1]) {
				case 'D': PCAP_DEBUG = strtoul(argv[i+1], NULL, 16); printf("\ndebug key:0x%x", PCAP_DEBUG); i++; break;
				case 'v': Config.VLAN   = atoi(&argv[i][2]); if (PCAP_DEBUG & pcap_dbg_cfg) printf("\ninclude VLANs:%u", Config.VLAN); break;
				case 'a': Config.append = atoi(&argv[i][2]); if (PCAP_DEBUG & pcap_dbg_cfg) printf("\nappend outfile:%u", Config.append); break;
				case 'l': Config.learn  = atoi(&argv[i][2]); if (PCAP_DEBUG & pcap_dbg_cfg) printf("\nlearn mode:%u", Config.learn); break;
				case 'w': Config.scan_limit++; 		     if (PCAP_DEBUG & pcap_dbg_cfg) printf("\nscan twice:%u", Config.scan_limit); break;
				case 'o': Config.outfilename = strcpy(calloc(strlen(argv[i+1])+1, 1), argv[i+1]); i++; break;
				case 'r': Config.condfilename= strcpy(calloc(strlen(argv[i+1])+1, 1), argv[i+1]); i++; break;
				case 'i': i++; while( (i < argc) && (argv[i][0] != '-') ) add_U_Condition(Config.Infiles, 'f', argv[i++]);  
					  i--; break;
				case 'c': switch(argv[i][2]) { 	   case 'i':  case 'm':  case 'c': case 'g': case 'd':
										add_U_Condition(Config.Conditions, argv[i][2], argv[i+1]); i++;
										break;
			     				           case 't':   	tid = strtoul(argv[i+1], NULL, 16);
										add_U_Condition(Config.Conditions, 't', &tid); i++;
										break;
					   			   case 'p':	ptid[0] = strtoul(argv[i+1], NULL, 16);
										ptid[1] = strtoul(strchr(argv[i+1], ':')+1, NULL, 16);
										if (PCAP_DEBUG & pcap_dbg_cfg) printf("TID PAIR %x %x", ptid[0], ptid[1]);
										add_U_Condition(Config.Conditions, 'p', ptid); i++;
										break;
								   case 'f':    incondfile = fopen(argv[i+1], "r");
										if (!incondfile) {printf("\nCannot open %s", argv[i+1]); stop = 1; break;}
										read_ConditionList(Config.Conditions, incondfile); i++;
										Config.append = 1;
										break;
								default: printf("\nUnknown condition option '-c%c' ignored", argv[i][2]); stop = 1; break;
					    			} // switch contidion type		
					    break; // command for condition
				default: printf("\nUnknown command '-%c' ignored", argv[i][1]); stop = 1; break;
				};  break; // switch command '-'
		  default:  printf("\nUrecognized argument '%s' ignored", argv[i]); stop = 1; break;
		} // switch arg
} // for args

Config.Infiles = sort_FileList(Config.Infiles);

if (PCAP_DEBUG & pcap_dbg_cfg)  {printf("\nOutput file:%s", Config.outfilename); printf("\n\nInput files:"); print_ConditionList(Config.Infiles, stdout);}
if (PCAP_DEBUG & pcap_dbg_cond) {printf("\n\nInitial conditions:"); print_ConditionList(Config.Conditions, stdout);}

if (!Config.outfilename) {printf("\nNo output file specified!\n%s", help_banner);  return(0);}

if (stop) {printf("\nExecution stopped!\n", help_banner);  return(0);}

outfile = create_pcap(Config.outfilename, Config.append);
if (!outfile) {printf("\nCannot create outfile %s", Config.outfilename); return(-1);}

for(Config.scan_counter = Config.scan_limit; Config.scan_counter; Config.scan_counter--) {
	for(fc = 0, Infile = (Condition*)Config.Infiles->buffer; fc < Config.Infiles->qty; Infile = next_Condition(Infile), fc++) { 
		if (PCAP_DEBUG & pcap_dbg_file) printf("\nFile:%s", Infile->cvalue);
		pkt_counter += process_file(Infile->cvalue, outfile, Config.Conditions);
		}
	}

fclose(outfile);
if ( (!packets_written) && (!Config.append) ) remove(Config.outfilename);
if (PCAP_DEBUG & pcap_dbg_cond) {printf("\nConditions at finish:"); print_ConditionList(Config.Conditions, stdout);}

if (Config.condfilename) {
	condfile = fopen(Config.condfilename, "w");
	if (condfile) print_ConditionList(Config.Conditions, condfile); 
	fclose(condfile);
	}

done_ConditionsList(Config.Infiles);
done_ConditionsList(Config.Conditions);

gettimeofday(&time_stop, NULL);
diff = (time_stop.tv_sec - time_start.tv_sec)*1000000 + (time_stop.tv_usec - time_start.tv_usec);

printf("\nTotal packets:%u time:%u ms, rate:%u pkt/sec", pkt_counter, diff/1000, 1000*pkt_counter/diff );

} // main

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int check_conditions(TConditionsList * CList, TPacket *pkt){
int j, match;
Condition *cond;

 for(j = 0, cond = (Condition*)CList->buffer; j < CList->qty; cond = next_Condition(cond), j++) { 
		if (pkt->protocol == pktSIP) { if ( cond->type=='c' ) if ( !strcmp(pkt->Fields.SIP.CallID, cond->cvalue)) return 1;
					       if ( cond->type=='m' ) if ( strstr(pkt->Fields.SIP.From,    cond->cvalue) 
									|| strstr(pkt->Fields.SIP.To,      cond->cvalue)) return 1;
		}//SIP
		if ( (pkt->protocol == pktMAP) || (pkt->protocol == pktCAP) ) switch(cond->type) {
			case 't': if ( (cond->t1 == pkt->Fields.TCAP.OTID) || (cond->t1 == pkt->Fields.TCAP.DTID)) return 1;
				break;
			case 'g': case 'i': case 'm':
				  if ( strstr(pkt->Fields.SCCP.GT_A, cond->cvalue)  || strstr(pkt->Fields.SCCP.GT_B, cond->cvalue) ) return 1;
				break;
			case 'p': if ( pkt->Fields.TCAP.OTID && pkt->Fields.TCAP.DTID && 
					( ( (cond->t1 == pkt->Fields.TCAP.OTID) && ( cond->t2 == pkt->Fields.TCAP.DTID) )   
				      ||  ( (cond->t1 == pkt->Fields.TCAP.DTID) && ( cond->t2 == pkt->Fields.TCAP.OTID) ) ))  return 1;
				break;                            
		} //TCAP
		if (pkt->protocol == pktMAP) {
					      if ( cond->type == 'm' )  if (strstr(pkt->Fields.MAP.MSISDN, cond->cvalue)) return 1;
					      if ( cond->type == 'i' )  if (strstr(pkt->Fields.MAP.IMSI,   cond->cvalue)) return 1;
		} //MAP
		if (pkt->protocol == pktCAP) {
					      if ( cond->type=='m' )  if ( strstr(pkt->Fields.CAP.MSISDN_A, cond->cvalue) ||
									   strstr(pkt->Fields.CAP.MSISDN_B, cond->cvalue) ||
									   strstr(pkt->Fields.CAP.MSISDN_C, cond->cvalue) ) return 1;
					      if ( cond->type=='i' )  if ( strstr(pkt->Fields.CAP.IMSI,     cond->cvalue) ) return 1;
		} //CAP
		if (pkt->protocol == pktDIAM) { 
					      if ( cond->type=='m' )  if ( strstr(pkt->Fields.DIAMETER.MSISDN,    cond->cvalue) ||
									   strstr(pkt->Fields.DIAMETER.Called,    cond->cvalue) ||
									   strstr(pkt->Fields.DIAMETER.Calling,   cond->cvalue)) return 1;
					      if ( cond->type=='i' )  if ( strstr(pkt->Fields.DIAMETER.IMSI,      cond->cvalue)) return 1;
					      if ( cond->type=='d' )  if (!strcmp(pkt->Fields.DIAMETER.SessionID, cond->cvalue)) return 1;
		} //DIAMETER
	}// for cond
return 0;
} // check conditions
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void add_conditions(TConditionsList * CList, TPacket *pkt) {
	if (!Config.learn) return;
	if (pkt->protocol == pktSIP) {
						      add_U_Condition(CList, 'c', pkt->Fields.SIP.CallID);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.SIP.From);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.SIP.To);
				}
	if (pkt->protocol == pktDIAM) {
				                      add_U_Condition(CList, 'd', pkt->Fields.DIAMETER.SessionID);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.DIAMETER.Called);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.DIAMETER.Calling);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.DIAMETER.MSISDN);
				if (Config.learn > 1) add_U_Condition(CList, 'i', pkt->Fields.DIAMETER.IMSI);
				}
	if (pkt->protocol == pktMAP) {
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.MAP.MSISDN);
				if (Config.learn > 1) add_U_Condition(CList, 'i', pkt->Fields.MAP.IMSI);
				}
	if (pkt->protocol == pktCAP) {
				if (Config.learn > 1) add_U_Condition(CList, 'i', pkt->Fields.CAP.IMSI);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.CAP.MSISDN_A);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.CAP.MSISDN_B);
				if (Config.learn > 1) add_U_Condition(CList, 'm', pkt->Fields.CAP.MSISDN_C);
				}                      
	if ((pkt->protocol == pktCAP) || (pkt->protocol == pktMAP)) { // TCAP
				if (!pkt->Fields.TCAP.DTID) add_U_Condition(CList, 't', &pkt->Fields.TCAP.OTID);
				if (!pkt->Fields.TCAP.OTID) add_U_Condition(CList, 't', &pkt->Fields.TCAP.DTID);
				if (pkt->Fields.TCAP.OTID && pkt->Fields.TCAP.DTID) add_U_Condition(CList, 'p', &pkt->Fields.TCAP.OTID);
				}
}// add conditions
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int pkt_handler(TConditionsList * CList, TPacket *pkt){
 int match;
 match = check_conditions(CList, pkt);
 if (match) add_conditions(CList, pkt);
 return match;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

int process_file(const char *filename, FILE* outfile, TConditionsList * CList){
// declarations
Packet_header packet_header;
Capture_header  *capture_header;
unsigned char pack_buf[BUF_SIZE];
TPCAPFile *PCAP;
TPacket pkt;
int cnt;
unsigned char match;
cnt=0;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
PCAP = pcap_open(filename);
if (!PCAP) return(0);

while (!pcap_endof(PCAP)) {
cnt++;
if (pcap_read(PCAP, &pkt)) 
		if (!( !(Config.VLAN) && (pkt.sll == 129))) // skip VLANs if need
			{
	if (PCAP_DEBUG & pcap_dbg_pkt)	printf("\n#%u hdr_size:%d prot:%u port:[%d][%d] size:[%d] time:%u", cnt, sizeof(pkt.packet_header),pkt.ip2_protocol, pkt.sport, pkt.dport, pkt.size, pkt.packet_header.ts_sec);
	if (PCAP_DEBUG & pcap_dbg_cond) print_ConditionList(CList,stdout);
  	match=pkt_parse(&pkt, (int (*)(void *, struct TPacket *))pkt_handler, CList); 
	// dumb filter mode
 	if (CList->qty==0 && pkt.protocol) {pcap_write(outfile, &pkt);	packets_written++;} 

	if (PCAP_DEBUG & pcap_dbg_print) pkt_print(&pkt);
	if (match) {	if (PCAP_DEBUG & pcap_dbg_match) printf("\nmatch!"); 
			if (Config.scan_counter == 1) {pcap_write(outfile, &pkt); packets_written++;}
		} // if match
	} // if read(pkt)
} // while feof PCAP

pcap_free(PCAP);
return cnt;
} // process_file
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// end of file
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
