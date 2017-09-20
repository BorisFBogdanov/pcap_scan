#include <stdio.h>
#include "pcap_stat.h"

#define PCAP_MAGIC (0xA1B2C3D4)
#define GZIP_MAGIC (0x8B1F)

// enough to fit one packet
#define BUF_SIZE (0x10000)
#define SIP_BUFFER   4000
#define SIP_LINES_QTY 300
#define Filename_Buf_Length 	(2048)

#define SIP_Field_Length 	(200)
#define IMSI_FIELD_LENGTH 	(200)
#define MSISDN_FIELD_LENGTH 	(200)
#define DIAMETER_FIELD_LENGTH 	(200)
#define DIAMETER_AVP_BUF_SIZE  (2048)

#define MIN_PORT_SIP 5060
#define MAX_PORT_SIP 5070

#define MIN_PORT_SMPP 2700
#define MAX_PORT_SMPP 2800

#define MIN_PORT_SCTP 2990
#define MAX_PORT_SCTP 4400

#define MIN_PORT_DIAM 2990
#define MAX_PORT_DIAM 3900

#define SIP_PREFIX_FROM    "FROM: "
#define SIP_PREFIX_TO      "TO: "
#define SIP_PREFIX_CALL_ID "CALL-ID: "
#define SIP_PREFIX_SIP	   "<SIP:"

#define pktMAP   1
#define pktCAP   2
#define pktSIP   4
#define pktDIAM  8
#define pktSMPP 16
#define pktNONE  0

// controlled debug
#define pcap_dbg_file 		0x000001
#define pcap_dbg_pkt  		0x000002
#define pcap_dbg_sip  		0x000004
#define pcap_dbg_diam 		0x000008
#define pcap_dbg_m2pa 		0x000010
#define pcap_dbg_m3ua 		0x000020
#define pcap_dbg_sctp 		0x000040
#define pcap_dbg_map  		0x000080
#define pcap_dbg_cap  		0x000100
#define pcap_dbg_diam_avp 	0x000200
#define pcap_dbg_bytes	 	0x000400
#define pcap_dbg_print	 	0x000800
#define pcap_dbg_sccp	 	0x001000
#define pcap_dbg_tcap  		0x002000
#define pcap_dbg_cond  		0x004000
#define pcap_dbg_match 		0x008000
#define pcap_dbg_cfg 	       	0x010000
#define pcap_dbg_smpp 	       	0x020000


extern unsigned int PCAP_DEBUG;

#define DEBUG 0

//typedef struct PCAP_header PCAP_header;
typedef  struct  { int magic; int version; int gmt; int accuracy; int snaplen; int dltype;} PCAP_header; // not useful

typedef struct  {int ts_sec; int ts_usec; int incl_len; int orig_len;} Packet_header;
typedef struct  {char ptypeh; char ptypel; char atypeh; char atypel; char alenh; char alenl;} Capture_header;

typedef struct TPCAPFile TPCAPFile;
struct  TPCAPFile {TPCAPFile *Self; 
		char *filename; 
		FILE *filehandler; 
		int gzipped; 
		int counter; 
		PCAP_header pcap_header; 
		unsigned char *packet_buf; 
		size_t buf_size; 
		Stat_Record stat_record;
};

typedef struct  TPacket TPacket;
struct  TPacket {TPacket *Self; 
		int size; 
		int ip_version; 
		int ip_header_length; 
		int ip_packet_length; 
		unsigned char sll; 
		unsigned char ip2_protocol; 
		unsigned short sport; 
		unsigned short dport; 
		Packet_header packet_header; 
		const char *packet_ptr; 
		const char *content_ptr;
		char protocol;
		struct { struct { char From[SIP_Field_Length];
				  char To[SIP_Field_Length];
				  char CallID[SIP_Field_Length];
				} SIP;
			struct {  char MSISDN[MSISDN_FIELD_LENGTH];
				  char IMSI[IMSI_FIELD_LENGTH];
				  char SessionID[SIP_Field_Length];
				  char Called[SIP_Field_Length];
				  char Calling[SIP_Field_Length];
				  char _temp_buffer[IMSI_FIELD_LENGTH];
				  unsigned char _subs_type;
				} DIAMETER;
			struct { char GT_A[MSISDN_FIELD_LENGTH];
				 unsigned char SSN_A;
				 char GT_B[MSISDN_FIELD_LENGTH];
				 unsigned char SSN_B;
				} SCCP;
			struct { unsigned int OTID;
				 unsigned int DTID; 
				} TCAP;
			struct { char IMSI[IMSI_FIELD_LENGTH];
                                 char MSISDN[MSISDN_FIELD_LENGTH];
				 unsigned char OpCode;
				} MAP;
			struct { char IMSI[IMSI_FIELD_LENGTH];
                                 char MSISDN_A[MSISDN_FIELD_LENGTH];
                                 char MSISDN_B[MSISDN_FIELD_LENGTH];
                                 char MSISDN_C[MSISDN_FIELD_LENGTH];
				 unsigned char OpCode;
				} CAP;
			struct { char MSISDN_A[MSISDN_FIELD_LENGTH];
                                 char MSISDN_B[MSISDN_FIELD_LENGTH];
				 unsigned int SEQUENCE;
				 unsigned int MESSAGE_ID;
				} SMPP;
			} Fields;
};

/* methods */
TPCAPFile* pcap_open(const char *);
void pcap_close(TPCAPFile *);
void pcap_free(TPCAPFile *);
int  pcap_endof(TPCAPFile *);
int pcap_read(TPCAPFile *, TPacket *);
int pcap_write(FILE *, TPacket *);
FILE *create_pcap(const char *, int);

int pkt_parse(TPacket*, int (*handler)(void *, TPacket *, Stat_Record *), void *, Stat_Record *);

void pkt_print(const TPacket *);
void clear_pkt(TPacket *);

char * normal(char *number); // sip number normalization
// end of file

