#include <stdio.h>

typedef struct Stat_proto Stat_proto;
struct Stat_proto {int read; 
		   int write; 
		   int match; 
};

typedef struct Stat_Record Stat_Record;
struct  Stat_Record {
		   Stat_proto all__stat; 
		   Stat_proto sip__stat; 
		   Stat_proto m2pa_stat; 
		   Stat_proto m3ua_stat; 
		   Stat_proto sccp_stat; 
		   Stat_proto tcap_stat; 
		   Stat_proto map__stat; 
		   Stat_proto cap__stat; 
		   Stat_proto diam_stat; 
		   Stat_proto smpp_stat; 
		   Stat_proto skip_stat; 
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void stat_record_init(Stat_Record *);
Stat_Record *stat_record_sum(Stat_Record *, Stat_Record *);
Stat_proto *stat_proto_sum(Stat_proto *, Stat_proto *);
void stat_proto_init(Stat_proto *);
Stat_Record *stat_record_total(Stat_Record *);
void stat_print(Stat_Record *, FILE*);
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
