#include <stdio.h>
#define INITIAL_LIST_SIZE   20000
#define INCREMENT_LIST_SIZE  4000

#define CONDFILE_LINE_BUFFER 16096
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
typedef struct Condition Condition;
struct  Condition {char type; unsigned int t1; unsigned int t2; short length; char cvalue[1];};

typedef struct TConditionsList TConditionsList;
struct TConditionsList {int qty; int size; int last_ptr; unsigned char * buffer;};
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void add_U_Condition(TConditionsList *, char, void*);

TConditionsList * init_ConditionsList();
void done_ConditionsList(TConditionsList *);
void print_ConditionList(TConditionsList *, FILE*);
void read_ConditionList(TConditionsList *, FILE*);
TConditionsList * sort_FileList(TConditionsList *);
Condition * next_Condition(Condition *);
// end of file
