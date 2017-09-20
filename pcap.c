#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "gsm.h"
#include "pcap.h"

/*internal methods */
void process_sip			(const unsigned char *, size_t, TPacket * );
 int process_smpp			(const unsigned char *, size_t, TPacket * , int (*handler)(void *, TPacket *, Stat_Record * ), void * , Stat_Record *);
 int process_diameter			(const unsigned char *, size_t, TPacket * , int (*handler)(void *, TPacket *, Stat_Record * ), void * , Stat_Record *);
 int process_sctp			(const unsigned char *, size_t, TPacket * , int (*handler)(void *, TPacket *, Stat_Record * ), void * , Stat_Record *);
 int process_m3ua			(const unsigned char *, 	TPacket * , int (*handler)(void *, TPacket *, Stat_Record * ), void * , Stat_Record *);
 int process_m2pa			(const unsigned char *, 	TPacket * , int (*handler)(void *, TPacket *, Stat_Record * ), void * , Stat_Record *);
void process_sccp			(const unsigned char *, 	TPacket *, Stat_Record *);
void process_tcap			(const unsigned char *, unsigned char, unsigned char, TPacket *);
void process_map			(const unsigned char *, size_t, TPacket * );
void process_map_component		(const unsigned char *, size_t, TPacket * );
void process_cap			(const unsigned char *, size_t, TPacket * );
void process_invoke			(const unsigned char *, size_t, TPacket * );
void process_camel_arg			(const unsigned char *, unsigned char, TPacket * );
void process_AVP(const unsigned char *, int, int, TPacket *, int *, int );

/* utils */
char * get_bcd_gt    (const unsigned char *buf, char *bcdnumber, size_t asn_length);
char * get_bcd_msisdn(const unsigned char *buf, char *bcdnumber, size_t asn_length);
char * get_imsi      (const unsigned char *buf, char *bcdnumber, size_t asn_length);

/* constants */
#define AVP_tree_maxdepth 10
unsigned int PCAP_DEBUG;
const char *digit = "0123456789ABCDEF";
const char *rmask = "\x01\x02\x04\x08\x10\x20\x40\x80\x00";
struct AVP {unsigned int code; unsigned char flags; int length; int vnd; unsigned char value[DIAMETER_AVP_BUF_SIZE];};
/* methods */
void prbyte(const unsigned char* ptr, int qty) {int i; printf("\n"); for(i = 0; i < qty; i++) printf(" %02X", ptr[i]);} // only for debug

/* T PCAP object */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* FEOF */
int pcap_endof(TPCAPFile *Self){ return feof(Self->filehandler); }
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* read packet */
int pcap_read(TPCAPFile *Self, TPacket *PKT){
Capture_header *capture_header;
int i, base;

if (pcap_endof(Self)) return 0;
memset(PKT, 0, sizeof(TPacket));

	i = fread(&PKT->packet_header, 1, sizeof(Packet_header), Self->filehandler);
	if (i != sizeof(Packet_header)) {if (PCAP_DEBUG & pcap_dbg_file) printf("packet header read %u instead %u, filename=%s", i, sizeof(Packet_header), Self->filename); return 0;}
	if (PKT->packet_header.orig_len > Self->buf_size) {if (PCAP_DEBUG & pcap_dbg_file) printf("\nbuffer reallocated"); Self->buf_size = PKT->packet_header.orig_len; Self->packet_buf = realloc(Self->packet_buf, Self->buf_size);};
	i = fread(Self->packet_buf, 1, PKT->packet_header.orig_len, Self->filehandler);
	if (i != PKT->packet_header.orig_len) {if (PCAP_DEBUG & pcap_dbg_file) printf("packet body read %u instead %u", i, PKT->packet_header.orig_len); return 0;}

	PKT->packet_ptr = Self->packet_buf;
	capture_header = (Capture_header*)(Self->packet_buf);
	base = sizeof(Capture_header) + capture_header->alenl;
	PKT->sll = (Self->packet_buf[base+2]);
	base = base + 4 + ( (PKT->sll == 129)? 4 : 0);
	PKT->ip_version = Self->packet_buf[base];
	PKT->ip_header_length = (0x0F & PKT->ip_version) * 4;
	PKT->ip_packet_length = Self->packet_buf[base+2] * 256 + Self->packet_buf[base+3];
	PKT->ip_version =  (PKT->ip_version & 0xF0) >> 4;
	PKT->ip2_protocol = Self->packet_buf[base+9];
	base += PKT->ip_header_length;
	PKT->sport = Self->packet_buf[base]   * 256 + Self->packet_buf[base+1];
	PKT->dport = Self->packet_buf[base+2] * 256 + Self->packet_buf[base+3];
	base += 8;
	PKT->content_ptr = Self->packet_buf+base;
	PKT->size = PKT->ip_packet_length - 32;
	if (PKT->ip2_protocol==IP_SCTP) PKT->content_ptr += 4;
	if (PKT->ip2_protocol==IP_TCP)  PKT->content_ptr = Self->packet_buf + 68; // todo redesign it
return i;
}/* pcap_read */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* destructor */
void pcap_free(TPCAPFile *Self){
if (Self->filehandler) pcap_close(Self);
free(Self->filename);
free(Self->packet_buf);
free(Self);
} /* pcap_free */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* constructor */
TPCAPFile * pcap_open(const char* fname){

TPCAPFile *Self;
int packet_cnt=0; // packet counter

char gzfilename[Filename_Buf_Length];
// * * * * * * * * * 
if (strlen(fname) > Filename_Buf_Length) {printf("\n too long filename %s!\nfilename buf size=%u", Self->filename, Filename_Buf_Length); pcap_free(Self); return(NULL); }
if (!fname) return(NULL);
Self = calloc(1, sizeof(TPCAPFile));
if (!Self) return(NULL);
Self->filename =  strcpy(calloc(1, strlen(fname) + 1), fname);
Self->filehandler = fopen(Self->filename, "rb");
if (!Self->filehandler) { printf("\n cannot open %s!", Self->filename); pcap_free(Self); return(NULL);}
Self->packet_buf = calloc(1, BUF_SIZE);
if (!Self->packet_buf) { printf("\n cannot allocate buffer %u!", BUF_SIZE); pcap_free(Self); return(NULL);}

Self->buf_size = BUF_SIZE;
/* check magic number */
fread(&Self->pcap_header, 6, sizeof(int), Self->filehandler);
//printf("\n%u %d %d %d %d %d", Self->pcap_header.magic, Self->pcap_header.version, Self->pcap_header.gmt, Self->pcap_header.accuracy, Self->pcap_header.snaplen, Self->pcap_header.dltype);
if ((Self->pcap_header.magic & 0xFFFF) == GZIP_MAGIC ) {
				Self->gzipped = 1;
				fclose(Self->filehandler);
				sprintf(gzfilename, "gzip -dc %s", Self->filename);
				Self->filehandler = popen(gzfilename, "r");
				if (!Self->filehandler) { printf("\n cannot open GZIP %s! %s", gzfilename, strerror(errno)); pcap_free(Self); return(NULL);}
			        fread(&Self->pcap_header, 6, sizeof(int), Self->filehandler);
				}
if (Self->pcap_header.magic != PCAP_MAGIC) { printf("\n%s isn`t pcap file!", Self->filename); pcap_free(Self); return(NULL);};
return Self;
} /* pcap_open */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void pcap_close(TPCAPFile *Self){
if (Self->gzipped) { 	pclose(Self->filehandler); 
	} else 	{	fclose(Self->filehandler); }
} /* pcap_close */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
FILE* create_pcap(const char * filename, int append){
const PCAP_header PCAP_HDR =  {PCAP_MAGIC, 0x40002, 0, 0, 0xFFFF, 0x71}; //a1b2c3d4 40002 0 0 ffff 71
 FILE* fh;
 int i;
 if (append)  { fh = fopen(filename,"r"); 
		if (!fh) return create_pcap(filename, 0);
		fclose(fh);
		return fopen(filename,"ab+");
		}
 fh = fopen(filename,"wb");
 if (!fh) return fh;
 i = fwrite(&PCAP_HDR, sizeof(PCAP_HDR), 1, fh);
 return fh;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int pcap_write(FILE * outfile, TPacket * pkt){
 int i,j;

 if (PCAP_DEBUG & pcap_dbg_file) printf("\nwrite %u+%u bytes", sizeof(Packet_header), pkt->packet_header.orig_len);
 i = fwrite(&pkt->packet_header, 1, sizeof(Packet_header), outfile);
 if (i != sizeof(Packet_header)) printf("\nfwrite returned %u instead %u",i,sizeof(Packet_header));
 j = fwrite(pkt->packet_ptr, 1, pkt->packet_header.orig_len,  outfile);
 if (j != pkt->packet_header.orig_len) printf("\nfwrite returned %u instead %u", j, pkt->packet_header.orig_len);

 return i + j;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int pkt_parse(TPacket *pkt, int (*handler)(void *, TPacket *, Stat_Record * ), void * CList, Stat_Record *stat_record){
	if ((pkt->ip2_protocol == IP_UDP) && ((pkt->sport >= MIN_PORT_SIP) && (pkt->sport <= MAX_PORT_SIP) || (pkt->dport >= MIN_PORT_SIP) && (pkt->dport <= MAX_PORT_SIP)) ) /* SIP */ {
		pkt->protocol = pktSIP;
		process_sip(pkt->content_ptr, pkt->ip_packet_length, pkt);
		if (PCAP_DEBUG & pcap_dbg_sip) printf("\nSIP l=%u ", pkt->ip_packet_length);
		stat_record->sip__stat.read++;
	  	return  handler(CList, pkt, stat_record);
	} // sip
	if ((pkt->ip2_protocol == IP_SCTP) && ((pkt->sport >= MIN_PORT_SCTP) && (pkt->sport <= MAX_PORT_SCTP) || (pkt->dport >= MIN_PORT_SCTP) && (pkt->dport <= MAX_PORT_SCTP)) ) { 
		if (PCAP_DEBUG & pcap_dbg_sctp) printf("\nSCTP l=%u ", pkt->ip_packet_length);
		return process_sctp(pkt->content_ptr, pkt->ip_packet_length, pkt, handler, CList, stat_record);
	} // SCTP (m2ua, m3ua, diameter)
	if ((pkt->size > 120) && (pkt->ip2_protocol == IP_TCP) && ((pkt->sport >= MIN_PORT_DIAM) && (pkt->sport <= MAX_PORT_DIAM) || (pkt->dport >= MIN_PORT_DIAM) && (pkt->dport <= MAX_PORT_DIAM)) ) { 
		if (PCAP_DEBUG & pcap_dbg_diam) printf("\nDIAM l=%u ", pkt->ip_packet_length);
		return process_diameter(pkt->content_ptr, pkt->ip_packet_length, pkt, handler, CList, stat_record);
	} // Diameter over TCP

	if ((pkt->size > 30) && (pkt->ip2_protocol == IP_TCP) && ((pkt->sport >= MIN_PORT_SMPP) && (pkt->sport <= MAX_PORT_SMPP) || (pkt->dport >= MIN_PORT_SMPP) && (pkt->dport <= MAX_PORT_SMPP)) ) { 
		if (PCAP_DEBUG & pcap_dbg_smpp) printf("\nSMPP l=%u ", pkt->ip_packet_length);
		return process_smpp(pkt->content_ptr, pkt->ip_packet_length-52, pkt, handler, CList, stat_record);
	} // SMPP over TCP

return 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void get_number(char* target, const char* source){
int i, j;

for(j = 0, i = strstr(source, SIP_PREFIX_SIP) - source + strlen(SIP_PREFIX_SIP); (source[i] != '@') && source[i]; i++) if (source[i] != '+') target[j++] = source[i];
target[j] = 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void get_callid(char* target, const char* source){
int i, j;

for(j = 0, i = strstr(source, SIP_PREFIX_CALL_ID) - source + strlen(SIP_PREFIX_CALL_ID); (source[i] != '@') && source[i]; i++) target[j++] = source[i];
target[j] = 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void process_sip(const unsigned char *buf, size_t packet_size, TPacket *pkt){
char sipb[SIP_BUFFER];
const unsigned char *end_ptr;
int i; int len; int sl; int ptr;
struct {int qty; char* item[SIP_LINES_QTY];} strings;

end_ptr = strstr(buf,"\x0A\x0D\x0A\x0D");
if (!end_ptr) end_ptr = strstr(buf,"\x0D\x0A\x0D\x0A");
if (!end_ptr) return;
len = end_ptr - buf;
strncpy(sipb, buf, len); sipb[len] = 0;

strings.qty = 0;
for(i = 0; i < len; i++) { if ((sipb[i] == 0x0A) || (sipb[i] == 0x0D)) sipb[i] = 0; else sipb[i] = toupper(sipb[i]); }
ptr = 0; while(ptr <= len){ sl = strlen(sipb + ptr);
			if (sl) {strings.item[strings.qty] = sipb + ptr;
				 strings.qty++;
			  	 ptr += sl + 1;
				} else ptr++;
			}

for(i = 0; i < strings.qty; i++) {
	if ( !strncmp(strings.item[i], SIP_PREFIX_FROM,    strlen(SIP_PREFIX_FROM)))    get_number(pkt->Fields.SIP.From,   strings.item[i]);
	if ( !strncmp(strings.item[i], SIP_PREFIX_TO,      strlen(SIP_PREFIX_TO)))      get_number(pkt->Fields.SIP.To,	   strings.item[i]);
	if ( !strncmp(strings.item[i], SIP_PREFIX_CALL_ID, strlen(SIP_PREFIX_CALL_ID))) get_callid(pkt->Fields.SIP.CallID, strings.item[i]);
	}
} // process_sip
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int process_smpp(const unsigned char *buf, size_t packet_size, TPacket* pkt, int (*handler)(void *, TPacket *, Stat_Record *), void * CList, Stat_Record *stat_record){
int ptr, msg_len;
int match=0;
if (PCAP_DEBUG & pcap_dbg_smpp)  printf("\n SMPP: packet_size=%u", packet_size);

for(ptr = 0; ptr + msg_len < packet_size; ptr += msg_len) {
        msg_len = buf[ptr]*0x1000000 + buf[ptr+1]*0x10000 + buf[ptr+2]*0x100 + buf[ptr+3];
        if (PCAP_DEBUG & pcap_dbg_smpp)  printf("\n   SMPP:msg_len=%u, ptr=%u", msg_len, ptr);
	match |=  process_smpp_msg(buf+ptr, msg_len, pkt, handler, CList, stat_record);
	}
return match;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int process_smpp_msg(const unsigned char *buf, size_t packet_size, TPacket* pkt, int (*handler)(void *, TPacket *, Stat_Record *), void * CList, Stat_Record *stat_record){
unsigned int command, length, result, sequence;
int ptr,  o_type, o_np, o_len, e_type, e_np, e_len;
int match;
const char *service;
if (PCAP_DEBUG & pcap_dbg_smpp && PCAP_DEBUG & pcap_dbg_bytes)  prbyte(buf, 18);

pkt->protocol = pktSMPP;

length	 = buf[ 0]*0x1000000 + buf[ 1]*0x10000 + buf[ 2]*0x100 + buf[ 3];
if (length<16) return 0;
command  = buf[ 4]*0x1000000 + buf[ 5]*0x10000 + buf[ 6]*0x100 + buf[ 7];
if ((command & 0x7FFFFFFF) == SMPP_ENQ_LINK) return 0;
result   = buf[ 8]*0x1000000 + buf[ 9]*0x10000 + buf[10]*0x100 + buf[11];
sequence = buf[12]*0x1000000 + buf[13]*0x10000 + buf[14]*0x100 + buf[15];
pkt->Fields.SMPP.SEQUENCE = sequence;
//if (command & 0x80000000) 
if (PCAP_DEBUG & pcap_dbg_smpp )  printf("\n     SMPP: command=%x length=%u", command, length);
ptr	= 16;
switch(command) {
 case SMPP_DATA_SM:
 case SMPP_SUBMIT_SM:
 case SMPP_DELIVER_SM:
			service = buf+ptr;
	                ptr 	+= strlen(service)+1;
			if (PCAP_DEBUG & pcap_dbg_smpp )  printf("\n     SMPP: service=%s", service);
 case SMPP_ALERT:	
			o_type	= buf[ptr++];
			o_np	= buf[ptr++];
			o_len	= strlen(buf+ptr);
 			if (ptr+o_len>length) break;
			if (o_type == SMPP_TON_Int) strcpy(pkt->Fields.SMPP.MSISDN_A, buf+ptr);
			if (PCAP_DEBUG & pcap_dbg_smpp )  printf("\n     SMPP: type %x, np %x MSISDN_A=%s", o_type, o_np, pkt->Fields.SMPP.MSISDN_A);
			ptr +=  o_len+1;
			e_type 	= buf[ptr++];
			e_np 	= buf[ptr++];
			e_len	= strlen(buf+ptr);
 			if (ptr+e_len>length) break;
 			if (e_type == SMPP_TON_Int) strcpy(pkt->Fields.SMPP.MSISDN_B, buf+ptr); 
			if (PCAP_DEBUG & pcap_dbg_smpp )  printf("\n     SMPP: type %x, np %x MSISDN_B=%s", e_type, e_np, pkt->Fields.SMPP.MSISDN_B);
			ptr 	+=  e_len+1;
			break;
}

match = handler(CList, pkt, stat_record);
stat_record->diam_stat.read++;
if (match) { stat_record->diam_stat.match++;}
return match;	
}// sprocess_smpp
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int process_diameter(const unsigned char *buf, size_t packet_size, TPacket* pkt, int (*handler)(void *, TPacket *, Stat_Record *), void * CList, Stat_Record *stat_record){
struct Diam {unsigned char version; int length; unsigned char flags; int command; int application_id; int hop_hop_id; int end_end_id; unsigned char req;} diam;
struct AVP avp;
int avp_ptr, sub_avp_ptr;
int avp_code_tree[AVP_tree_maxdepth];
int match;

if (PCAP_DEBUG & pcap_dbg_diam &&  PCAP_DEBUG & pcap_dbg_bytes)  prbyte(buf, 18);

pkt->protocol = pktDIAM;

diam.version = buf[0];
diam.length  = (int)buf[1] * 0x10000 +  (int)buf[2] * 0x100 + buf[3];
diam.flags   = buf[4];
diam.req     = diam.flags & 0x80;
diam.command = buf[5] * 0x10000 +  buf[6] * 0x100 + buf[7];
diam.application_id = buf[8] * 0x1000000 + buf[9] * 0x10000 +  buf[10] * 0x100 + buf[11];
//diam.hop_hop_id = buf[12]<<24 + buf[13]<<16 +  buf[14]<<8 + buf[15];
//diam.end_end_id = buf[16]<<24 + buf[17]<<16 +  buf[18]<<8 + buf[19];
if (PCAP_DEBUG & pcap_dbg_diam) printf("\n Diameter: command=%u length=%u, app-id=%u, flags=%x", diam.command, diam.length, diam.application_id, diam.flags);
switch (diam.command) {
	case DIAM_Watch_Dog 		: return 0;
	case DIAM_CREDIT_CONTROL	:
	case DIAM_3GPP_UPDATE_LOCATION	:
	case DIAM_3GPP_CANCEL_LOCATION	:
	case DIAM_3GPP_AUTH_INFO	:	
	case DIAM_3GPP_DELETE_DATA	:	
	case DIAM_3GPP_PURGE_UE 	:	
	case DIAM_3GPP_RESET 		:
	case DIAM_3GPP_NOTIFY 		:
	case DIAM_3GPP_IMEI_CHECK 	: 
	case DIAM_3GPP_INSERT_DATA	:	
				        avp_code_tree[0] = diam.command;
					process_AVP(buf+20, diam.length-8, diam.command, pkt, avp_code_tree, 0);
	}// diam command
match = handler(CList, pkt, stat_record);
stat_record->diam_stat.read++;
if (match) { stat_record->diam_stat.match++;}
return match;	
}// process_diameter
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

void process_AVP(const unsigned char *buf, int avp_length, int diam_command, TPacket *pkt, int * avp_tree_code, int level){
int avp_ptr, body_length;
const unsigned char * body_ptr;
struct AVP avp;
for(avp_ptr = 0; avp_ptr < avp_length-12; avp_ptr += avp.length){ 
	avp.code = buf[avp_ptr] * 0x1000000 + buf[avp_ptr+1] * 0x10000 +  buf[avp_ptr+2] * 0x100 + buf[avp_ptr+3];
	avp.flags = buf[avp_ptr+4];
	avp.length = buf[avp_ptr+5] * 0x10000 +  buf[avp_ptr+6] * 0x100 + buf[avp_ptr+7];
	body_length = avp.length - 8;
	if (avp.length % 4) avp.length += ( 4 - (avp.length % 4) );
	body_ptr = buf + avp_ptr + 8;
	if (avp.flags & 0x80 ) {  // Vendor TAG presence
			avp.vnd = buf[avp_ptr+8] * 0x1000000 + buf[avp_ptr+9] * 0x10000 +  buf[avp_ptr+10] * 0x100 + buf[avp_ptr+11]; 
			body_ptr    += 4;
			body_length -= 4;
			}
	if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    AVP: LEVEL %u, code=%u length=%u, avp_ptr=%u", level, avp.code, avp.length, avp_ptr);
		switch(avp.code) {
			case DIAM_AVP_SMS_INFO 			:
			case DIAM_AVP_Service_Information	:
			case DIAM_AVP_SMS_Recipient_INFO	:
			case DIAM_AVP_SMS_Recipient_Address	:
			case DIAM_AVP_SMS_Originator_INFO  	:
			case DIAM_AVP_IMS_Information  		:
			case DIAM_AVP_Subscription_Data		:
 						avp_tree_code[level+1] = avp.code;
						process_AVP(body_ptr, body_length, diam_command, pkt, avp_tree_code, level+1); 
						break; // for grouped AVPs
			case DIAM_AVP_SubscriptionID 		:
 						avp_tree_code[level+1] = avp.code;
						pkt->Fields.DIAMETER._temp_buffer[0] = 0;
						process_AVP(body_ptr, body_length, diam_command, pkt, avp_tree_code, level+1); 
						if (strlen(pkt->Fields.DIAMETER._temp_buffer)) 
							switch (pkt->Fields.DIAMETER._subs_type) {
								case DIAM_END_USER_IMSI  : if (atol(pkt->Fields.DIAMETER._temp_buffer))  strcpy(pkt->Fields.DIAMETER.IMSI,   pkt->Fields.DIAMETER._temp_buffer); 
											   if (PCAP_DEBUG & pcap_dbg_diam) printf("\n     IMSI str=%s", pkt->Fields.DIAMETER.IMSI);
									break;
								case DIAM_END_USER_MSISDN: if (pkt->Fields.DIAMETER._temp_buffer[0] == '1' && pkt->Fields.DIAMETER._temp_buffer[1] == '1')
												strcpy(pkt->Fields.DIAMETER.MSISDN, pkt->Fields.DIAMETER._temp_buffer+2); 
											    else
												strcpy(pkt->Fields.DIAMETER.MSISDN, pkt->Fields.DIAMETER._temp_buffer); 
								if (PCAP_DEBUG & pcap_dbg_diam) printf("\n   MSISDN str=%s", pkt->Fields.DIAMETER.MSISDN);
									break;
								}	
						break;
			case DIAM_AVP_SubscriptionID_Type	: pkt->Fields.DIAMETER._subs_type = buf[11]; 
								break;
			case DIAM_AVP_SubscriptionID_Data	: if ((avp.length-8) > DIAMETER_FIELD_LENGTH) {printf("\nAVP value length (%u) exceed DIAMETER_FIELD_LENGTH (%u)", avp.length-8, DIAMETER_FIELD_LENGTH); return;}
	 							  strncpy(pkt->Fields.DIAMETER._temp_buffer, body_ptr, body_length); pkt->Fields.DIAMETER._temp_buffer[body_length] = 0; 
								if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER._temp_buffer);
                        					break;
			case DIAM_AVP_SessionID			: strncpy(pkt->Fields.DIAMETER.SessionID, body_ptr, body_length); pkt->Fields.DIAMETER.SessionID[body_length] = 0; 
								if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.SessionID);
								break;                                                     
			case DIAM_AVP_USER_NAME:strncpy(pkt->Fields.DIAMETER.IMSI, body_ptr, body_length);  pkt->Fields.DIAMETER.IMSI[body_length] = 0; 
						if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.IMSI);
						break;                                                     
			case DIAM_AVP_Called_Party : strncpy(pkt->Fields.DIAMETER.Called,  body_ptr+2, body_length);     pkt->Fields.DIAMETER.Called [body_length]=0; 
						if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.Called);
						break;
			case DIAM_AVP_Calling_Party: strncpy(pkt->Fields.DIAMETER.Calling, body_ptr+2, body_length);     pkt->Fields.DIAMETER.Calling[body_length]=0; 
						if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.Calling);
						break;
			case DIAM_AVP_MSISDN: get_imsi(body_ptr, pkt->Fields.DIAMETER.MSISDN,  body_length); 
						if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s, l=%u", pkt->Fields.DIAMETER.MSISDN, body_length);
						break;
			case DIAM_AVP_SMS_Address_Data: switch (avp_tree_code[level]) {
								case DIAM_AVP_SMS_Originator_INFO :strncpy(pkt->Fields.DIAMETER.Calling, body_ptr, body_length); 
												pkt->Fields.DIAMETER.Calling[body_length]=0;
												if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.Calling);
												break;
								case DIAM_AVP_SMS_Recipient_Address:strncpy(pkt->Fields.DIAMETER.Called, body_ptr, body_length); 
												pkt->Fields.DIAMETER.Called[body_length]=0;
												if (PCAP_DEBUG & pcap_dbg_diam) printf("\n    str=%s", pkt->Fields.DIAMETER.Called);
												break;
							} ;
						break;
				
		} // switch avp.code
	} // for avp
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// local utilites
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// parse buf, return bcdnumber
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
char* get_bcd_gt(const unsigned char *buf, char *bcdnumber, size_t length){
int i, j;
for(i = 2, j = 0; i < length; i++){
 bcdnumber[j++] = digit[ buf[i] & 0x0F];
 bcdnumber[j++] = digit[(buf[i] & 0xF0) >> 4];
	}
if (buf[0] & 0x80) j--; // odd
bcdnumber[j] = 0;
return bcdnumber;
}// get_bcd_gt
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// parse buf, return bcdnumber
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
char* get_bcd_gt_sccp(const unsigned char *buf, char *bcdnumber, size_t length){
int i, j;

for(i = 3, j = 0; i < length; i++){
 bcdnumber[j++] = digit[ buf[i] & 0x0F];
 bcdnumber[j++] = digit[(buf[i] & 0xF0) >> 4];
	}
if (!(buf[1] & 0x02)) j--; 
bcdnumber[j] = 0;
return bcdnumber;
}// get_bcd_gt
// parse buf, return bcdnumber
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
char* get_bcd_msisdn(const unsigned char *buf, char *bcdnumber, size_t length){
int i,j;
for(i = 1, j = 0; i < length; i++){
 bcdnumber[j++] = digit[ buf[i] & 0x0F];
 bcdnumber[j++] = digit[(buf[i] & 0xF0) >> 4];
}
if (buf[0] & 0x80) j--; // odd
bcdnumber[j] = 0;
return bcdnumber;
}// get_bcd_msisdn
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// parse buf, returns bcdbumber
char* get_imsi(const unsigned char *buf, char *bcdnumber, size_t length){
int i, j;
for(i = 0, j = 0; i < length; i++){
 bcdnumber[j++] = digit[ buf[i] & 0x0F];
 bcdnumber[j++] = digit[(buf[i] & 0xF0) >> 4];
}
if (bcdnumber[j-1] == 'F') j--;
bcdnumber[j] = 0;
return bcdnumber;
}// get_imsi
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

// return length of ASN component, and moves count_ptr
int get_d_asn(const unsigned char *buf, int* count_ptr){
int acc,i,l;
  if (buf[0] == 0x80) { for(i=1; (buf[i] | buf[i+1]); i++); *count_ptr += 1; return i-1; } // 00
  if (buf[0] & 0x80) {
	// extract length
	l = (buf[0] & 0x7F); acc = 0;
	if (l==0) {*count_ptr += 2; return buf[2];}
	for(i=1; i<=l; i++){ acc += buf[i];}
	*count_ptr += i;
	return acc;	
   } else {
	*count_ptr += 1; return buf[0];
	}
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// return length of ASN component, and moves count_ptr
int tcap_get_d_asn(const unsigned char *buf, int* count_ptr, int limit){
int acc,i,l;
  if (buf[0] == 0x80) { 
			for(i=1; (buf[i] | buf[i+1] | buf[i+2] | buf[i+3]) && (i+3 < limit); i++); 
			if (buf[i] & buf[i+1] & buf[i+2] & buf[i+3]) {	*count_ptr += 1; return i+3;} // 0000 termination
			for(i=1; (buf[i] | buf[i+1] ) && (i+1 < limit); i++); 
			 *count_ptr += 1; return i+1;	 // 00 termination
		      }
  if (buf[0] & 0x80) {
	// extract length
	l = (buf[0] & 0x7F); acc = 0;
	if (l==0) {*count_ptr += 2; return buf[2];}
	for(i=1; i<=l; i++){ acc += buf[i];}
	*count_ptr += i;
	return acc;	
   } else {
	*count_ptr += 1; return buf[0];
	}
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

// return length of ASN component, and moves count_ptr
int get_dd_asn(const unsigned char *buf, int* count_ptr){
  if (buf[0] == 0x80) return get_d_asn(buf+1, count_ptr+1);
	   	 else return get_d_asn(buf, count_ptr);
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
char * normal(char *number){ // !!! adjust this for your network specific issues
unsigned char *p;
	if (number[0] == '+') number++;
	if ((strlen(number) == 11) && (number[0] == '7') && (number[1] != '0')) number++;
	p = strchr(number, 'D');	if (p) number = p + 5;
	p = strchr(number, '%');	if (p) number = p + 3;
	p = strchr(number, '#');	if (p) number = p + 1;
	if (number[0] == 'E') number += 5;
	if (number[0] == '+') number++;

	if ((strlen(number) == 11) && (number[0] == '7') && (number[1] != '0')) number++;
return number;	
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int process_sctp(const unsigned char *buf, size_t packet_size, TPacket * pkt, int (*handler)(void *, TPacket *, Stat_Record *), void * CList, Stat_Record *stat_record){
int chunk_type, chunk_length, payload;
int ptr=0;
int match;
match = 0;
while (ptr < packet_size-32) {
 chunk_type = buf[ptr];
 chunk_length = buf[ptr+2] * 256 + buf[ptr+3];
if (PCAP_DEBUG & pcap_dbg_sctp) printf("\n packet size=%u, ptr=%u", packet_size, ptr);
if (PCAP_DEBUG & pcap_dbg_sctp) printf("\n   chunk type=0x%x, chunk length=%u\n",chunk_type, chunk_length);
if (chunk_length % 4) {chunk_length = (((chunk_length) / 4) +1) * 4;} // Aligment!

 if (chunk_type == 0) { // data chunk
	payload = buf[ptr+15];
	if (PCAP_DEBUG & pcap_dbg_sctp) printf("\n   			 payload=%u\n", payload);
	if (payload ==  3) {  match += process_m3ua(buf+ptr+16, pkt, handler, CList, stat_record);	}
	if (payload ==  5) {  match += process_m2pa(buf+ptr+15, pkt, handler, CList, stat_record);	}
	if (payload == 46) {  match += process_diameter(buf+ptr+16, packet_size-ptr-16, pkt, handler, CList, stat_record); }
	}
 ptr+=chunk_length;
};
return match;
}// process_sctp

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
int process_m3ua(const unsigned char *buf, TPacket * pkt, int (*handler)(void *, TPacket *, Stat_Record *), void * CList, Stat_Record *stat_record){
int class, payload, message_length, tag, tag_len, ptr;
int match = 0;
if (PCAP_DEBUG & pcap_dbg_m3ua & pcap_dbg_bytes)  prbyte(buf, 8);
 class = buf[2];
 if (class != 3) {
	if (PCAP_DEBUG & pcap_dbg_m3ua) printf("\n m3ua class %u", class);
	payload = buf[3];
	message_length =  buf[6] * 256 + (buf[7]);
	if (PCAP_DEBUG & pcap_dbg_m3ua) printf(" mess_len:%u", message_length);
	for(ptr = 8; ptr < message_length-8; ){
		tag     = buf[ptr  ] * 256 + buf[ptr+1];
		tag_len = buf[ptr+2] * 256 + buf[ptr+3];
		if (PCAP_DEBUG & pcap_dbg_m3ua) printf("\n      tag: %04x, length=%u",tag, tag_len);
		if (tag == 0x0210) {clear_pkt(pkt);
			 	    process_sccp(buf+ptr+16, pkt, stat_record); 
				    match += handler(CList, pkt, stat_record);
					}
		ptr += tag_len;
		}
	}
return match;
} // process_m3ua;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

int process_m2pa(const unsigned char *buf, TPacket * pkt,int (*handler)(void *, TPacket *, Stat_Record*), void * CList, Stat_Record *stat_record){
int size, message_type, match;
 stat_record->m2pa_stat.read++;
 message_type = buf[4];
 match = 0;
 if (message_type != 1) return 0; // User Data only
 size = buf[7]*256 + buf[8];
// if (class != 3) {
if (PCAP_DEBUG & pcap_dbg_m2pa)  printf("\n m2pa %u", size);
//	}
if (size<32) return 0; // ignore bullshit
	process_sccp(buf+23, pkt, stat_record);
        match = handler(CList, pkt, stat_record);
	if (match) { stat_record->m2pa_stat.match++;}
return match;	
} // process_m3ua;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void process_sccp(const unsigned char *buf, TPacket * pkt, Stat_Record *stat_record){
int called_ptr, calling_ptr, tcap_ptr;
unsigned char s_ssn, d_ssn;
unsigned char called_len, calling_len, ext_data, message_type;
char bcdnumber[MSISDN_FIELD_LENGTH];

	stat_record->sccp_stat.read++;

if (PCAP_DEBUG & pcap_dbg_sccp & pcap_dbg_bytes) { printf("\nSCCP:"); prbyte(buf,8);}
        ext_data = 0;
	message_type = buf[0];
	if (message_type == 0x11) ext_data = 1;
	called_ptr =  buf[2+ext_data];
	calling_ptr = buf[3+ext_data];
	tcap_ptr =    buf[4+ext_data];
	s_ssn = buf[4+called_ptr+ext_data];
	d_ssn = buf[5+calling_ptr+ext_data];
	called_len =  buf[2+called_ptr+ext_data];
	calling_len = buf[3+calling_ptr+ext_data];

	if (PCAP_DEBUG & pcap_dbg_sccp ) printf(" called len=%02X", called_len);
	if (PCAP_DEBUG & pcap_dbg_sccp ) printf(" calling len=%02X",calling_len);

	if (called_len >MSISDN_FIELD_LENGTH) {printf("\bCalled len %u exceed buffer %u", called_len ,MSISDN_FIELD_LENGTH); return;}
	if (calling_len>MSISDN_FIELD_LENGTH) {printf("\bCalling len %u exceed buffer %u",calling_len,MSISDN_FIELD_LENGTH); return;}

	get_bcd_gt_sccp(buf+called_ptr+5, bcdnumber, called_len-2);
	strcpy(pkt->Fields.SCCP.GT_B, bcdnumber);

	get_bcd_gt_sccp(buf+calling_ptr+6,bcdnumber, calling_len-2);
	strcpy(pkt->Fields.SCCP.GT_A, bcdnumber);

	pkt->Fields.SCCP.SSN_A = s_ssn;
	pkt->Fields.SCCP.SSN_B = d_ssn;

	process_tcap(buf+tcap_ptr+5+ext_data, s_ssn, d_ssn, pkt);
	if (s_ssn==SSN_CAP) {stat_record->cap__stat.read++;}
		       else {stat_record->map__stat.read++;}
} // process_sccp;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

void process_tcap(const unsigned char *buf, unsigned char s_ssn, unsigned char d_ssn, TPacket * pkt){
unsigned char message_type, asn_tag;
int ptr, message_length, asn_length, limit;
int otid, dtid;
	if ( (PCAP_DEBUG & pcap_dbg_tcap) && (PCAP_DEBUG & pcap_dbg_bytes)) {printf("\nTCAP:"); prbyte(buf,18);}
        ptr = 0;
	message_type = buf[0];
	message_length = get_d_asn(buf+1, &ptr); limit = ptr+message_length;
	if (PCAP_DEBUG & pcap_dbg_tcap) printf("\nTCAP: s_ssn:%u d_ssn:%u m_type:%X m_length:%u ptr:%u",s_ssn, d_ssn, message_type, message_length, ptr);
	ptr++;
	while (ptr < message_length) {
		asn_tag = buf[ptr]; 
		if (!asn_tag) {ptr++; continue;}
		asn_length = tcap_get_d_asn(buf+ptr+1, &ptr, message_length); if (asn_length>message_length) {asn_length = message_length;};
		if (PCAP_DEBUG & pcap_dbg_tcap) printf("\nTCAP: asn_tag:0x%X asn_length:0x%X", asn_tag, asn_length);

		if (asn_tag == TCAP_OTID) {
			otid = *((int*)(buf+ptr+1));
			pkt->Fields.TCAP.OTID = otid;
			if (PCAP_DEBUG & pcap_dbg_tcap) printf("\n   OTID - %x", otid);
			}
		if (asn_tag == TCAP_DTID) {
			dtid = *((int*)(buf+ptr+1));
			pkt->Fields.TCAP.DTID = dtid;
			if (PCAP_DEBUG & pcap_dbg_tcap) printf("\n   DTID - %x", dtid);
			}
		if (asn_tag == TCAP_P_ABORT) { //asn_length = limit-ptr; 
			if (PCAP_DEBUG & pcap_dbg_tcap) printf("\ntcap P-Abort, tag=0x%x, len=0x%x", asn_tag, asn_length);
			}
		if (asn_tag == TCAP_DIALOGUE) { //asn_length = limit-ptr; 
//			asn_length = tcap_dialogue_length(buf+ptr+1);
			if (PCAP_DEBUG & pcap_dbg_tcap) printf("\ntcap Dialogue, tag=0x%x, len=0x%x", asn_tag, asn_length);
			}
		if (asn_tag == TCAP_COMPONENT) { asn_length = limit-ptr; 	// workaround. assume this is last asn tag
			if (PCAP_DEBUG & pcap_dbg_tcap) printf("\ntcap Component, tag=0x%x, len=0x%x", asn_tag, asn_length);
			if ((s_ssn == SSN_CAP) || (d_ssn == SSN_CAP)) process_cap(buf+ptr+1, asn_length, pkt); 
						                 else process_map(buf+ptr+1, asn_length, pkt); 
			}
		ptr += asn_length+1;
		if (ptr > limit+1) {printf("\nASN length %u exceed size %u", ptr, limit); return;}
	}
} // process_tcap;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void process_map(const unsigned char *buf, size_t map_length, TPacket *pkt){
unsigned char asn_tag, opcode;
int ptr, asn_length;
ptr=0;
pkt->protocol = pktMAP;
while (ptr < map_length) {
	asn_tag = buf[ptr];
	if (!asn_tag) break;
	asn_length = get_d_asn(buf+ptr+1, &ptr);
	if (PCAP_DEBUG & pcap_dbg_map)  printf("\n MAP  tag=%X  tag_len=%X", asn_tag, asn_length);
	if (asn_tag==0x6C)  process_map(buf+ptr+1, asn_length, pkt);
	if (asn_tag==0xA1)  process_map_component(buf+ptr+1, asn_length, pkt);
	ptr += asn_length+1;
	}
} // process_map;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void process_map_component(const unsigned char *buf, size_t map_length, TPacket *pkt){
unsigned char asn_tag, opcode, imsi_len, isd_tag;
int ptr, asn_length;
char bcdnumber[MSISDN_FIELD_LENGTH];

ptr=5; // skip invoke
opcode = buf[ptr]; 

if (PCAP_DEBUG & pcap_dbg_map)  printf("\nMAP   opcode:0x%X", opcode);

ptr++;
while (ptr < map_length){
	asn_tag = buf[ptr];
	if (!asn_tag) break;

	asn_length = get_d_asn(buf+ptr+1, &ptr);
	if (PCAP_DEBUG & pcap_dbg_map) printf("\n  map tag:%X len:%X", asn_tag, asn_length);

	pkt->Fields.MAP.OpCode = opcode;	

	if ((asn_tag == 0x30) && (opcode == MAP_sendAuthenticationInfo)) {
		imsi_len = buf[ptr+2];
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nSAI imsi_len  [%u]", imsi_len);
		get_imsi(buf+ptr+3, bcdnumber, imsi_len);
		strcpy(pkt->Fields.MAP.IMSI, bcdnumber);
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nSAI imsi %s", bcdnumber);
		break;
	}

	if ((asn_tag == 0x30) && (opcode == MAP_sendRoutingInfo || opcode == MAP_sendRoutingInfoForSM) ) {
		get_bcd_msisdn(buf+ptr+3, bcdnumber, buf[ptr+2]);
		strcpy(pkt->Fields.MAP.MSISDN, bcdnumber);
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nSRI[sm] msisdn %s", bcdnumber);
		break;
	}

	if (asn_tag == 0x30 && opcode == MAP_provideRoamingNumber) {
		imsi_len = buf[ptr+2];
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nPRN imsi_len  [%u]", imsi_len);
		get_imsi(buf+ptr+3, bcdnumber, imsi_len);
		strcpy(pkt->Fields.MAP.IMSI, bcdnumber);
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nPRN imsi %s", bcdnumber);
		break;
	}

	if (asn_tag == 0x30 && ( (opcode == MAP_updateLocation) || (opcode == MAP_updateGprsLocation)  ) ) {
		imsi_len = buf[ptr+2];
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nLU imsi_len  [%u]", imsi_len);
		get_imsi(buf+ptr+3, bcdnumber, imsi_len);
		strcpy(pkt->Fields.MAP.IMSI, bcdnumber);
		if (PCAP_DEBUG & pcap_dbg_map) printf("\nLU imsi %s", bcdnumber);
		break;
	}

	if (asn_tag == 0x30 && opcode == MAP_insertSubscriberData) {
		if (buf[ptr+2] > 20 || buf[ptr+2] < 3) break; // not MSISDN
		isd_tag = buf[ptr+1];
		if (PCAP_DEBUG & pcap_dbg_map) printf("\n   isd_tag:%x", isd_tag);
		if (isd_tag == 0x81) {
			get_bcd_msisdn(buf+ptr+3, bcdnumber, buf[ptr+2]);
			strcpy(pkt->Fields.MAP.MSISDN, bcdnumber);
			if (PCAP_DEBUG & pcap_dbg_map) printf("\nISD msisdn %s", bcdnumber);
			}
		break;
	}
	ptr += asn_length+1;
	}

} // process_map_component
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

void process_cap(const unsigned char *buf, size_t cap_length, TPacket *pkt){
unsigned char asn_tag, opcode;
int ptr, asn_length;
ptr=0;
pkt->protocol = pktCAP;
if ((PCAP_DEBUG & pcap_dbg_cap) && (PCAP_DEBUG & pcap_dbg_bytes) ) prbyte(buf, 20);
while (ptr < cap_length){
	asn_tag = buf[ptr];
	if (!asn_tag) return;
	asn_length = get_d_asn(buf+ptr+1, &ptr);
	if (PCAP_DEBUG & pcap_dbg_cap)  printf("\n cap component %x %x",asn_tag, asn_length);
	process_invoke(buf+ptr+1, asn_length, pkt);
	ptr += asn_length+1;
	}
}
 // process_cap;
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void process_invoke(const unsigned char *buf, size_t cap_length, TPacket *pkt){
int ptr, asn_len, asn_tag;
int invoke_tag, invoke_len, invoke_val, opcode_tag, opcode_len, opcode;
asn_tag = buf[ptr];
ptr = 0;
invoke_tag = buf[0];
invoke_len = buf[1];
ptr = 1 + invoke_len;
invoke_val = buf[ptr];
if (PCAP_DEBUG & pcap_dbg_cap)  printf("\n invoke:  tag=%x len=%x val=%x", invoke_tag, invoke_len, invoke_val);

opcode_tag = buf[ptr+1];
opcode_len = buf[ptr+2];
ptr += 2 + opcode_len;
opcode = buf[ptr];
if (PCAP_DEBUG & pcap_dbg_cap)  printf("\n opcode  tag=%x len=%x val=%x", opcode_tag, opcode_len, opcode);

asn_tag = buf[ptr+1];
asn_len = get_d_asn(buf+ptr+2, &ptr);
pkt->Fields.CAP.OpCode = opcode;
if (PCAP_DEBUG & pcap_dbg_cap)  printf("\n CAP OPCODE %u",opcode);
if (PCAP_DEBUG & pcap_dbg_cap)  printf("\n CAP  asn_tag: %X  length:%X - op=%u", asn_tag, asn_len, opcode);
if ((opcode == CAP_IDP) || (opcode == CAP_Connect)){ process_camel_arg(buf+ptr, opcode, pkt);}

}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 

void process_camel_arg(const unsigned char *buf, unsigned char opcode, TPacket *pkt){
unsigned char arg_code;
int ptr, asn_length, arg_length, asn_tag;
char bcdnumber[MSISDN_FIELD_LENGTH];

ptr=0;
arg_code = buf[0];
arg_length = get_d_asn(buf+ptr+1, &ptr);
ptr++;
if (PCAP_DEBUG & pcap_dbg_cap) printf(" argcode=%u arglen=%u ", arg_code, arg_length);
while (ptr < arg_length){
	asn_tag = buf[ptr];
	if (asn_tag == 0x9F || asn_tag == 0xBF) { asn_tag = asn_tag*256 + buf[++ptr]; };
	asn_length = get_d_asn(buf+ptr+1, &ptr);	
	if (PCAP_DEBUG & pcap_dbg_cap)	printf("\n	 ptr=%u CAP-ARG:%X-%X", ptr, asn_tag, asn_length);

	if ( (opcode == CAP_IDP) && (asn_tag == CAP_I_CalledPN) )
				{ 
				get_bcd_gt(buf+ptr+1, bcdnumber, asn_length); 
				strcpy(pkt->Fields.CAP.MSISDN_B, bcdnumber);
				if (PCAP_DEBUG & pcap_dbg_cap) printf("\nCalled_PN %s",bcdnumber);
				}; 
	if ( (opcode == CAP_IDP) && (asn_tag == CAP_I_CallingPN) ) 
				{ 
				get_bcd_gt(buf+ptr+1, bcdnumber, asn_length); 
				strcpy(pkt->Fields.CAP.MSISDN_A, bcdnumber);
				if (PCAP_DEBUG & pcap_dbg_cap) printf("\nCalling_PN %s",bcdnumber);
				}; 
	if ( ((opcode == CAP_IDP) && (asn_tag == CAP_I_IMSI)))
				{ 
				get_imsi(buf+ptr+1, bcdnumber, asn_length); 
				strcpy(pkt->Fields.CAP.IMSI, bcdnumber);
				if (PCAP_DEBUG & pcap_dbg_cap) printf("\nIMSI %s",bcdnumber);
				}; 
	if	((opcode == CAP_Connect) && (asn_tag == 0xA0))  { // todo replace with define
				asn_tag = buf[++ptr]; ptr++;
				asn_length = get_d_asn(buf+ptr, &ptr);
				get_bcd_gt(buf+ptr, bcdnumber, asn_length); 
				strcpy(pkt->Fields.CAP.MSISDN_C, bcdnumber);
				if (PCAP_DEBUG & pcap_dbg_cap) printf("\nConnect_To %s",bcdnumber);
				};
	ptr += asn_length+1;
}
} // process_camel_arg
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void pkt_print(const TPacket* pkt){
if (pkt->protocol == pktSIP) {
         printf("\nSIP: From:%s To:%s CallID:%s", pkt->Fields.SIP.From, pkt->Fields.SIP.To, pkt->Fields.SIP.CallID);
	}
if (pkt->protocol == pktDIAM) {
         printf("\nDIAM: {IMSI:%s,MSISDN:%s} From:%s To:%s SessionID:%s", pkt->Fields.DIAMETER.IMSI, pkt->Fields.DIAMETER.MSISDN, pkt->Fields.DIAMETER.Calling, pkt->Fields.DIAMETER.Called, pkt->Fields.DIAMETER.SessionID);
	}
if (pkt->protocol == pktMAP || pkt->protocol == pktCAP) {
         printf("\nSCCP: GT_a:%s ssn_a:%u GT_b:%s ssn_b:%u", pkt->Fields.SCCP.GT_A, pkt->Fields.SCCP.SSN_A, pkt->Fields.SCCP.GT_B, pkt->Fields.SCCP.SSN_B);
         printf("\n  TCAP: OTID:%0X DTID:%0X", pkt->Fields.TCAP.OTID, pkt->Fields.TCAP.DTID);
if (pkt->protocol == pktMAP) {
		printf("\n    MAP: OP:%u IMSI:%s MSISDN:%s", pkt->Fields.MAP.OpCode, pkt->Fields.MAP.IMSI,pkt->Fields.MAP.MSISDN);
		}
if (pkt->protocol == pktCAP) {
		printf("\n    CAP: OP:%u IMSI:%s MSISDN_A:%s, MSISDN_B:%s, MSISDN_C:%s,", pkt->Fields.CAP.OpCode, pkt->Fields.CAP.IMSI,pkt->Fields.CAP.MSISDN_A,pkt->Fields.CAP.MSISDN_B,pkt->Fields.CAP.MSISDN_C);
		}
if (pkt->protocol == pktSMPP) {
		printf("\n   SMPP: MSISDN_A:%s, MSISDN_B:%s, seq:%u, m_id:%X", pkt->Fields.SMPP.MSISDN_A, pkt->Fields.SMPP.MSISDN_B, pkt->Fields.SMPP.SEQUENCE, pkt->Fields.SMPP.MESSAGE_ID);
		}
	}
} // pkt_print
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
void clear_pkt(TPacket* pkt){
pkt->Fields.SIP.From[0]		=0;
pkt->Fields.SIP.To[0]		=0;
pkt->Fields.SIP.CallID[0]	=0;
pkt->Fields.SCCP.GT_A[0]	=0;
pkt->Fields.SCCP.GT_B[0]	=0;
pkt->Fields.SCCP.SSN_A		=0;
pkt->Fields.SCCP.SSN_B		=0;
pkt->Fields.DIAMETER.MSISDN[0]	=0;
pkt->Fields.DIAMETER.IMSI[0]	=0;
pkt->Fields.DIAMETER.SessionID[0]=0;
pkt->Fields.DIAMETER.Called[0]	=0;
pkt->Fields.DIAMETER.Calling[0]	=0;
pkt->Fields.TCAP.OTID		=0;
pkt->Fields.TCAP.DTID		=0;
pkt->Fields.MAP.IMSI[0]		=0;
pkt->Fields.MAP.MSISDN[0]	=0;
pkt->Fields.MAP.OpCode		=0;
pkt->Fields.CAP.OpCode		=0;
pkt->Fields.CAP.IMSI[0]		=0;
pkt->Fields.CAP.MSISDN_A[0]	=0;
pkt->Fields.CAP.MSISDN_B[0]	=0;
pkt->Fields.CAP.MSISDN_C[0]	=0;
pkt->Fields.SMPP.MSISDN_A[0]	=0;
pkt->Fields.SMPP.MSISDN_B[0]	=0;
pkt->Fields.SMPP.SEQUENCE	=0;
pkt->Fields.SMPP.MESSAGE_ID	=0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
// end of file
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
