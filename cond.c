#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cond.h"
#include "pcap.h"

// internal declarations
struct Files {char *name; time_t mtime;};

void add_Condition(TConditionsList *, char, void*); // dont call from external scope
void printCondition(int, void* );
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
TConditionsList * init_ConditionsList(){
 TConditionsList * Self;
 Self = calloc(1, sizeof(TConditionsList));
 Self->qty = 0;
 Self->size = INITIAL_LIST_SIZE;
 Self->buffer = calloc(1, INITIAL_LIST_SIZE);
 Self->last_ptr = 0;
return Self;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void done_ConditionsList(TConditionsList * Self){
free(Self->buffer);
free(Self);
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void add_U_Condition(TConditionsList *Self, char Type, void* Value){
Condition * cond;
int i;
unsigned int p1, p2;
void *value;
value = Value;
if (PCAP_DEBUG & pcap_dbg_cond) {printf("\nadd U condition %c\n", Type); printCondition(Type, value);}
if (PCAP_DEBUG & pcap_dbg_cond) print_ConditionList(Self, stdout);
if (( Type == 't' || Type == 's' || Type == 'x' ) && ( *(int*)(value) == 0) ) return; // don't use empty TID;
if (( Type != 't' && Type != 's' && Type != 'x' && Type != 'p') && ( strlen(value) == 0) ) {if (PCAP_DEBUG & pcap_dbg_cond) printf("\nskip empty line"); return;}; // don't use empty fields;
if  ( Type != 't' && Type != 's' && Type != 'x' && Type != 'p') value = normal((char*)(value)); // skip % # prefix 
for(i = 0, cond = (Condition*)Self->buffer; i < Self->qty; cond = (Condition*)((char*)cond + cond->length), i++){  
	if (cond->type == Type) switch(Type) {
		case 't': case 's': case 'x':
			  if (PCAP_DEBUG & pcap_dbg_cond) printf(" comparing %x %x\n", *(unsigned int*)(value), cond->t1);
			  if  (*(unsigned int*)(value) == cond->t1) return; break;
		case 'p': 
			  p1 = *    (unsigned int*)(value);
			  p2 = * (1+(unsigned int*)(value));
			  if (PCAP_DEBUG & pcap_dbg_cond) printf(" comparing %x:%x %x:%x\n", *(unsigned int*)(value),* (1 + (unsigned int*)(value)), cond->t1, cond->t2);
			  if ( (p1 == cond->t1) && (p2 == cond->t2) ) return; 
			  if ( (p2 == cond->t1) && (p1 == cond->t2) ) return; 
			  break;
		 default: if (PCAP_DEBUG & pcap_dbg_cond) printf(" comparing %s %s\n",cond->cvalue, value);
			  if ( !strcmp(cond->cvalue, value) ) return; break;
		}
	}
if (PCAP_DEBUG & pcap_dbg_cond) printf(" new condition!\n");
add_Condition(Self, Type, value);
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void add_Condition(TConditionsList *Self, char Type, void* Value){
int vl, chunk_size;
Condition * C_ptr;

if (!Type) return;
switch(Type){
	case 't': case 'p': case 's': case 'x': vl = 1; break;
  	 default: vl = strlen(Value)+1;
}
chunk_size = sizeof(Condition)+vl;

if (PCAP_DEBUG & pcap_dbg_cond) printf("\nqty:%u, size:%u last:%u first:%x",Self->qty, Self->size, Self->last_ptr, Self->buffer);
if (Self->last_ptr + chunk_size > Self->size) {	Self->size += INCREMENT_LIST_SIZE;
						Self->buffer = realloc(Self->buffer, Self->size);
					}
Self->qty++;
C_ptr = (Condition*)(Self->buffer + Self->last_ptr);
C_ptr->type = Type;
C_ptr->length = chunk_size;
if (PCAP_DEBUG & (pcap_dbg_cond | pcap_dbg_bytes)) {printf("\nC_ptr: "); prbyte(C_ptr, 16);}
switch(Type){
	case 't' : case 's': case 'x':
		   C_ptr->t1 = *(unsigned int*)Value; 
		   if (PCAP_DEBUG & pcap_dbg_cond)  printf("\ntid added %x\n", C_ptr->t1);
		   break;
	case 'p' : C_ptr->t1 = *(unsigned int*)Value; C_ptr->t2 = *((unsigned int*)Value + 1);  
		   if (PCAP_DEBUG & pcap_dbg_cond)  printf("\npair added %x:%x\n", C_ptr->t1, C_ptr->t2);
		   break;
	  default: strcpy(C_ptr->cvalue,(char*)Value);
}

Self->last_ptr += chunk_size;
if (PCAP_DEBUG & (pcap_dbg_cond | pcap_dbg_bytes)) {printf("\nC_ptr: ");prbyte(C_ptr,16);}
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void print_ConditionList(TConditionsList * Self, FILE *file){
int i;
Condition * ptr;

if (PCAP_DEBUG & pcap_dbg_cond) printf("\ncond list, qty=%u size=%u Listptr=%x", Self->qty, Self->size, Self->buffer);
for(i = 0, ptr = (Condition*)Self->buffer; i < Self->qty; ptr = (Condition*)((char*)ptr + ptr->length), i++) { 
		switch(ptr->type){
			case   0: break;
			case 't': 
			case 'x': 
			case 's': fprintf(file, "\n%c %08X", ptr->type, ptr->t1); break;
			case 'p': fprintf(file, "\n%c %08X:%08X", ptr->type, ptr->t1, ptr->t2); break;
		  	 default: fprintf(file, "\n%c %s", ptr->type, ptr->cvalue); break;
			}
 	} 
} // printConditionList
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void printCondition(int type, void * value){
	switch(type){
		case   0: break;
		case 't': 
		case 'x': 
		case 's': printf("\n%c %08X", type, *(unsigned int*)value); break;
		case 'p': printf("\n%c %08X:%08X", type, *(unsigned int*)value, *(1+(unsigned int*)value)); break;
	  	 default: printf("\n%c [%s]",type, (char*)value); break;
			}
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void read_ConditionList(TConditionsList * Self, FILE* text){
char line[CONDFILE_LINE_BUFFER];
char type;
unsigned int ptid[2];
while( !feof(text) ){ 
	fgets(line, CONDFILE_LINE_BUFFER-1, text); type =line[0]; 
	if (line[strlen(line)-1] == 0x0A) line[strlen(line)-1] = 0; // CR/LF workaround

	switch (type){
		case 't': case 's': case 'x':
			  ptid[0] = strtoul(&line[2], NULL, 16);
 			  add_U_Condition(Self, type, ptid); 
   			  break;
		case 'p': ptid[0] = strtoul(&line[2], NULL, 16);
			  ptid[1] = strtoul(strchr(&line[2], ':')+1, NULL, 16);
   			  add_U_Condition(Self, 'p', ptid); break;
		case 'c': case 'm': case 'i': case 'a': 
			  add_U_Condition(Self, type, &line[2]); 
			  break;
		 default: break;
		}
	}
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int cmpFile(const void *p1, const void *p2){
time_t d;

d = ((struct Files *)(p1))->mtime - ((struct Files *)(p2))->mtime;
if (d > 0) return  1;
if (d < 0) return -1;
return 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

TConditionsList * sort_FileList(TConditionsList *FList){
struct Files * array;
struct stat fstat;
Condition * ptr;
TConditionsList * newlist; 
int i;

if (PCAP_DEBUG & pcap_dbg_cfg) printf("\nfile list to be sorted:");
array = calloc(sizeof(struct Files), FList->qty);
for(ptr = (Condition*)FList->buffer, i = 0; i < FList->qty; ptr = (Condition*)( (char*)ptr + ptr->length) , i++) { array[i].name = ptr->cvalue;}
for(i = 0; i < FList->qty; i++) {
			stat(array[i].name, &fstat);
			array[i].mtime = fstat.st_mtime;
			if (PCAP_DEBUG & pcap_dbg_cfg) printf("\ntime:%u size:%u  %s", fstat.st_mtime, fstat.st_size, array[i].name);
			}
qsort(array, FList->qty, sizeof(struct Files), cmpFile);
newlist = init_ConditionsList();

if (PCAP_DEBUG & pcap_dbg_cfg) printf("\nfile list sorted:");
for(i = 0; i < FList->qty; i++) { 
		if (PCAP_DEBUG & pcap_dbg_cfg) printf("\n%u %s", array[i].mtime, array[i].name);
		add_Condition(newlist, 'f', array[i].name);
		}
free(array);
done_ConditionsList(FList);
return newlist;
} // sort_FileList
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
Condition * next_Condition(Condition * ptr){
return (Condition*) ( (char*)ptr + ptr->length);
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// end of file
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
