#define MAX_PROCESS_NAME_LENGTH 26
#define MAX_PROCESS_TABLE_LENGTH 10

#include<stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include<signal.h>

typedef struct  PROCESS_INFO
{
    int pid;
    char name[MAX_PROCESS_NAME_LENGTH];
    float cpu;
    float mem;
} PROCESS_INFO;

void print_info(PROCESS_INFO* p_procces_info){
    printf("%i %s %f %f \n",p_procces_info->pid,p_procces_info->name,p_procces_info->cpu,p_procces_info->mem);
}

int kill_process(int pid){

    if(kill(pid,SIGTERM)==-1){
        return -1;
    }
    return 0;
}

PROCESS_INFO* create_procces_table(){

    char buffer[1024];
    
    PROCESS_INFO* table = malloc(MAX_PROCESS_TABLE_LENGTH*sizeof(PROCESS_INFO));
    
    FILE* fp = popen("ps -eo pid,comm,%cpu,%mem, --sort -%cpu --no-headers","r");
    
    int i =0;
    while(i<MAX_PROCESS_TABLE_LENGTH && fgets(buffer,sizeof(buffer),fp)!=NULL){
        sscanf(buffer,"%i %26s %f %f ",&table[i].pid,table[i].name,&table[i].cpu,&table[i].mem);
        i++;
    }
    pclose(fp);  
       
    return table;
}

void delete_process_table(PROCESS_INFO* p_process_info){
    free(p_process_info);
}

