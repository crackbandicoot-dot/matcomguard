#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"

typedef struct {
    int pid;
    char command[MAX_COMMAND_LENGTH];
    float cpu_sum;
    float mem_sum;
} ProcessData;

int contains_string(const char **array, const char *target) {
    for (int i = 0; array[i]; i++) {
        if (strcmp(array[i], target) == 0) return 1;
    }
    return 0;
}

void process_check() {
    ProcessData processes[MAX_PROCESSES];
    int process_count = 0;

    printf("Monitoring processes for %d seconds...\n", SAMPLE_TIME_SECONDS);
    
    
    for (int i = 0; i < MAX_PROCESSES; i++) {
        processes[i].pid = -1;
    }

    
    for (int sample = 0; sample < SAMPLE_TIME_SECONDS; sample++) {
        FILE *ps = popen("ps -eo pid,pcpu,pmem,comm --no-headers", "r");
        if (!ps) {
            perror("popen failed");
            return;
        }

        char line[MAX_LINE_LENGTH];
        while (fgets(line, sizeof(line), ps)) {
            int pid;
            float pcpu, pmem;
            char comm[MAX_COMMAND_LENGTH];
            
            
            if (sscanf(line, "%d %f %f %127s", &pid, &pcpu, &pmem, comm) != 4) 
                continue;

            
            int slot = -1;
            for (int i = 0; i < MAX_PROCESSES; i++) {
                if (processes[i].pid == pid) {
                    slot = i;
                    break;
                }
                if (slot == -1 && processes[i].pid == -1) {
                    slot = i;
                }
            }

            if (slot != -1) {
                if (processes[slot].pid != pid) {  
                    processes[slot].pid = pid;
                    strncpy(processes[slot].command, comm, MAX_COMMAND_LENGTH-1);
                    processes[slot].command[MAX_COMMAND_LENGTH-1] = '\0';
                    processes[slot].cpu_sum = 0;
                    processes[slot].mem_sum =0;
                    if (process_count < MAX_PROCESSES) process_count++;
                }
                
                processes[slot].cpu_sum += pcpu;
                processes[slot].mem_sum += pmem;
            }
        }
        pclose(ps);
        
        if (sample < SAMPLE_TIME_SECONDS - 1) {
            sleep(1);
        }
    }

    printf("\nSuspicious processes (exceeding thresholds):\n");
    printf("CPU > %.1f%% or MEM > %.1f%%\n", CPU_THRESHOLD, MEM_THRESHOLD);
    printf("--------------------------------------------\n");
    
    int detected = 0;
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (processes[i].pid == -1) continue;
        
        
        float avg_cpu = (processes[i].cpu_sum)/SAMPLE_TIME_SECONDS;
        float avg_mem = (processes[i].mem_sum)/SAMPLE_TIME_SECONDS;
            
        if ((avg_cpu > CPU_THRESHOLD || avg_mem > MEM_THRESHOLD)
        & !contains_string(TRUSTED_PROCESSES,processes[i].command) ) {
           
            printf("PID: %d\n", processes[i].pid);
            printf("Command: %s\n", processes[i].command);
            printf("Avg CPU: %5.1f%%, Avg MEM: %5.1f%%\n", avg_cpu, avg_mem);
            printf("--------------------------------------------\n");
            detected = 1;
            }
        }
    
    if (!detected) {
        printf("No suspicious processes found\n");
    }
}

