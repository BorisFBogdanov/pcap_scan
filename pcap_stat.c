#include  <string.h>
#include "pcap_stat.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void stat_record_init(Stat_Record *ptr){ memset(ptr, 0, sizeof(Stat_Record)); };
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void stat_proto_init(Stat_proto *ptr){ memset(ptr, 0, sizeof(Stat_proto)); };
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
Stat_Record *stat_record_total(Stat_Record *sum){
 stat_proto_init(&sum->all__stat);
 stat_proto_sum(&sum->all__stat, &sum->sip__stat);
 stat_proto_sum(&sum->all__stat, &sum->m2pa_stat);
 stat_proto_sum(&sum->all__stat, &sum->m3ua_stat);
 stat_proto_sum(&sum->all__stat, &sum->sccp_stat);
 stat_proto_sum(&sum->all__stat, &sum->tcap_stat);
 stat_proto_sum(&sum->all__stat, &sum->map__stat);
 stat_proto_sum(&sum->all__stat, &sum->cap__stat);
 stat_proto_sum(&sum->all__stat, &sum->diam_stat);
 stat_proto_sum(&sum->all__stat, &sum->smpp_stat);
 stat_proto_sum(&sum->all__stat, &sum->skip_stat);

 return sum;
};
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
Stat_Record *stat_record_sum(Stat_Record *sum, Stat_Record *add){
 stat_proto_sum(&sum->all__stat, &add->all__stat);
 stat_proto_sum(&sum->sip__stat, &add->sip__stat);
 stat_proto_sum(&sum->m2pa_stat, &add->m2pa_stat);
 stat_proto_sum(&sum->m3ua_stat, &add->m3ua_stat);
 stat_proto_sum(&sum->sccp_stat, &add->sccp_stat);
 stat_proto_sum(&sum->tcap_stat, &add->tcap_stat);
 stat_proto_sum(&sum->map__stat, &add->map__stat);
 stat_proto_sum(&sum->cap__stat, &add->cap__stat);
 stat_proto_sum(&sum->diam_stat, &add->diam_stat);
 stat_proto_sum(&sum->smpp_stat, &add->smpp_stat);
 stat_proto_sum(&sum->skip_stat, &add->skip_stat);
 return sum;
};
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
Stat_proto *stat_proto_sum(Stat_proto *sum, Stat_proto *add){
 sum->read  += add->read;
 sum->write += add->write;
 sum->match += add->match;
 return sum;
};
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void stat_print(Stat_Record *stat, FILE* outfile){
 fprintf(outfile, "\nproto   read match");
 fprintf(outfile, "\nDIAM:%6u %6u",stat->diam_stat.read, stat->diam_stat.match);
 fprintf(outfile, "\nSMPP:%6u %6u",stat->smpp_stat.read, stat->smpp_stat.match);
 fprintf(outfile, "\n SIP:%6u %6u",stat->sip__stat.read, stat->sip__stat.match);
 fprintf(outfile, "\nM2PA:%6u %6u",stat->m2pa_stat.read, stat->m2pa_stat.match);
 fprintf(outfile, "\nM3UA:%6u %6u",stat->m3ua_stat.read, stat->m3ua_stat.match);
 fprintf(outfile, "\nSCCP:%6u %6u",stat->sccp_stat.read, stat->sccp_stat.match);
 fprintf(outfile, "\nTCAP:%6u %6u",stat->tcap_stat.read, stat->tcap_stat.match);
 fprintf(outfile, "\n MAP:%6u %6u",stat->map__stat.read, stat->map__stat.match);
 fprintf(outfile, "\n CAP:%6u %6u",stat->cap__stat.read, stat->cap__stat.match);
 fprintf(outfile, "\nskip:%6u %6u",stat->skip_stat.read, stat->skip_stat.match);
 fprintf(outfile, "\n -----------------");
 stat_record_total(stat);                                                
 fprintf(outfile, "\n ALL:%6u %6u",stat->all__stat.read, stat->all__stat.match);
 fprintf(outfile, "\n =================");

};                                                
