#bin/bash
gcc -o matcomguard main.c procces_checker.c ports_checker.c discovery.c scanner.c baseline.c -lssl -lcrypto -ludev -lpthread
