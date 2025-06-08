#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "procces_checker.c"
#include "ports_checker.c"


void scan_usb()
{
}


int  main()
{
    printf("Welcome to the throne \n");
    while (1)
    {
        printf("Here u can make your subdits to do the following things:\n\n");
        printf("1-Patrol the Kingdom's Files(check USB devices)\n\n");
        printf("2-Inspect the Drawbridges(check proccesses)\n\n");
        printf("3-Guard the Castle Walls(check ports)\n\n");
        printf("4-General Mobilization!(check all)\n\n");
        printf("5-Leave Kingdom (Exit)\n\n");
        int option;
        scanf("%d", &option);
        
            switch (option)
            {
            case 1:
                scan_usb();
                break;
            case 2:
                process_check();
                break;
            case 3:
                check_ports();
                break;
            case 4:
                scan_usb();
                process_check();
                check_ports();
                break;
            case 5:
               return 0;
               break;
            default:
                printf("Invalid option. You must take a number betwen 1 and 4\n\n");
                break;
            }        
    }
    return 0;
}
