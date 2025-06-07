#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "procces_info.c"
#include "Ports Checker.c"

int main()
{

    PROCESS_INFO *p_process_table = create_procces_table();
    for (int i = 0; i < MAX_PROCESS_TABLE_LENGTH; i++)
    {
        print_info(&p_process_table[i]);
    }
    delete_process_table(p_process_table);
    check_ports();
}
