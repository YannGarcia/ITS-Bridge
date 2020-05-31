#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef void(*sigaction_signal_callback)(int, siginfo_t *, void *);

typedef enum {
  _starting,
  _running,
  _exiting,
  _reload
} state_t;

/**
 * \brief Parse the command-line parameters, setting the various globals that are affected by them.
 * \param[in] p_args Argument count
 * \param[in] p_argv Argument vector
 * \return 0 on success, -1 otherwise
 */
int32_t parse_params(const int p_argc, char* const p_argv[]);

int32_t parse_config_file(const char* p_config_file);

void free_config_file_resources(void);

char* bin2hex(char* p_hex, size_t p_hlen, const uint8_t* p_bin, size_t p_blen);

void usage(const char* p_progname, const uint8_t p_role);

int32_t set_pid_file(const char* p_pid_file);

char* get_pid_from_file(const char* p_pid_file);

int32_t set_lock_file(const char* p_lock_file);

void set_sigaction_signal(const int32_t p_signal, sigaction_signal_callback p_sigaction_handler);

void daemonize();

char* string_to_base64 (const char* p_message);

long get_file_size (const char* p_filename);

char* load_file (const char *p_filename);

int32_t load_binary_file(const char *p_filename, uint8_t** p_buffer, size_t* p_size);

int32_t save_configuration_file(const char *p_filename, const char* progname, ...);

char** str_split(const char* p_string, const char p_separator, size_t* p_num_addresses);
