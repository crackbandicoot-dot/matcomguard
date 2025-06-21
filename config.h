#ifndef CONFIG_H
#define CONFIG_H


#define SAMPLE_TIME_SECONDS 12
#define MAX_PROCESSES 1024
#define MAX_LINE_LENGTH 256
#define MAX_COMMAND_LENGTH 128

// Output control
#define ENABLE_VERBOSE 1      // 1 = enabled, 0 = disabled
#define SHOW_ALL_PROCESSES 0  // 1 = show all, 0 = only suspicious

// Trusted processes (won't be flagged)
const char *TRUSTED_PROCESSES[] = {
    "systemd",
    "sshd",
    "bash",
    "kernel",
    "dbus-daemon",
    "rsyslogd",
    "NetworkManager",
    "gmain",  // GLib main loop
    "gdbus"   // GLib D-Bus
};

// Number of trusted processes
#define N_TRUSTED (sizeof(TRUSTED_PROCESSES) / sizeof(TRUSTED_PROCESSES[0]))

#endif