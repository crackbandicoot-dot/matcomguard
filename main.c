#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "procces_info.c"
#include "Ports Checker.c"

void scan_filesystem()
{

    PROCESS_INFO *p_process_table = create_procces_table();
    for (int i = 0; i < MAX_PROCESS_TABLE_LENGTH; i++)
    {
        print_info(&p_process_table[i]);
    }
    delete_process_table(p_process_table);
    printf("\n\n");
}
void scan_usb()
{
}

int main()
{
    interface();
}
void interface()
{
    printf("\nWelcome to the throne \n");
    while (1)
    {
        printf("Here u can make your subdits to do the followin things:\n\n");
        printf("1-Patrol the Kingdom's Files\n\n");
        printf("2-Inspect the Drawbridges\n\n");
        printf("3-Guard the Castle Walls\n\n");
        printf("4-General Mobilization!\n\n");
        int option;
        scanf("%d", &option);
        if (option >= 1 && option <= 4)
        {
            switch (option)
            {
            case 1:
                scan_filesystem();
                break;
            case 2:
                scan_usb();
                break;
            case 3:
                check_ports();
                break;
            default:
                scan_filesystem();
                scan_usb();
                check_ports();
                break;
            }
        }
        else
        {
            printf("Invalid option. You must take a number betwin 1 and 4\n\n");
        }
    }
}
