#include "utils.h"

char* its_nic = NULL;
char* udp_nic = NULL;
char* mac_address = NULL;
char* udp_address = NULL;
char* udp_protocol = NULL;
char* config_file = NULL;
uint16_t udp_port = 5000;
bool daemonized = false;

char* login = NULL;
char* password = NULL;
char* realm = NULL;
char* cert_pem = NULL;
char* cert_key = NULL;
char* conf_path = NULL;
uint16_t https_port = 8888;

char* pid_file = NULL;
state_t state = _starting;

int32_t parse_params(const int p_argc, char* const p_argv[]) {
  int  option;
  int  args_left;
  while ((option = getopt(p_argc, p_argv, "a:c:dhi:m:n:p:u:v")) != -1) {
    switch (option) {
    case 'a':
      udp_protocol = optarg;
      break;
    case 'c':
      config_file = optarg;
      break;
    case 'd':
      daemonized = true;
      break;
    case 'i':
      udp_nic = optarg;
      break;
    case 'm':
      mac_address = optarg;
      break;
    case 'n':
      its_nic = optarg;
      break;
    case 'p':
      udp_port = (uint16_t)atoi(optarg);
      break;
    case 'u':
      udp_address = optarg;
      break;
    case 'h':
      /*No break;*/
    case 'v':
      return -2;
      break;
    default:
      return -1;
    }
  } /* End of 'while' statement */

  return 0;
}

int32_t parse_config_file(const char* p_config_file) {
  printf("parse_config_file: %s.\n", p_config_file);

  /* Open it */
  FILE* f = fopen(p_config_file, "r");
  if (f == NULL) {
    printf("parse_config_file: Failed to open %s: %s.\n", p_config_file, strerror(errno));
    return -1;
  }
  char line[256];
  char key[128];
  char value[128];
  char* left;
  char* right;
  char* inline_comment;
  while (fgets(line, 256, f)) {
    if (line[0] == '#') { /* Comment, skip it */
      continue;
    }
    if ((left = strstr(line, "=")) == NULL) { /* Malformed line, ignore it */
      continue;
    }
    strncpy(key, line, (size_t)(left - line));
    key[(size_t)(left - line)] = '\x00';
    printf("parse_config_file: key=%s\n", key);
    inline_comment = strstr(line, "#");
    right = strstr(line, "\n");
    if (inline_comment == NULL) {
      if (right == NULL) {
        strncpy(value, left + 1, strlen(line) - (size_t)left - 1);
        value[strlen(line) - (size_t)left - 1] = '\x00';
      } else {
        strncpy(value, left + 1, (size_t)(right - left - 1));
        value[(size_t)(right - left - 1)] = '\x00';
      }
    } else {
      // TODO
    }
    printf("parse_config_file: value=%s\n", value);
    if (strcmp(key, "daemon_mode") == 0) {
      if (strcmp(value, "0") == 0) {
        daemonized = false;
      } else {
        daemonized = true;
      }
    } else if (strcmp(key, "mac_address") == 0) {
      mac_address = strdup(value);
    } else if (strcmp(key, "its_nic") == 0) {
      its_nic = strdup(value);
    } else if (strcmp(key, "udp_nic") == 0) {
      udp_nic = strdup(value);
    } else if (strcmp(key, "udp_address") == 0) {
      udp_address = strdup(value);
    } else if (strcmp(key, "udp_protocol") == 0) {
      udp_protocol = strdup(value);
    } else if (strcmp(key, "udp_port") == 0) {
      udp_port = atoi(value);
    } else if (strcmp(key, "login") == 0) {
      login = strdup(value);
    } else if (strcmp(key, "password") == 0) {
      password = strdup(value);
    } else if (strcmp(key, "realm") == 0) {
      realm = strdup(value);
    } else if (strcmp(key, "cert_pem") == 0) {
      cert_pem = strdup(value);
    } else if (strcmp(key, "cert_key") == 0) {
      cert_key = strdup(value);
    } else if (strcmp(key, "conf_path") == 0) {
      conf_path = strdup(value);
    } else if (strcmp(key, "https_port") == 0) {
      https_port = atoi(value);
    }
  } /* End of 'while' statement */

  fclose(f);

  return 0;
}

void free_config_file_resources() {
  if (mac_address != NULL) {
    free(mac_address);
    mac_address = NULL;
  }
  if (its_nic != NULL) {
    free(its_nic);
    its_nic = NULL;
  }
  if (udp_nic != NULL) {
    free(udp_nic);
    udp_nic = NULL;
  }
  if (udp_address != NULL) {
    free(udp_address);
    udp_address = NULL;
  }
  if (udp_protocol != NULL) {
    free(udp_protocol);
    udp_protocol = NULL;
  }
  udp_port = 0;
}

char* bin2hex(char* p_hex, size_t p_hlen, const uint8_t* p_bin, size_t p_blen) {
  static const char* _hexDigits = "0123456789ABCDEF";
	const uint8_t *b, *e;
	char* s;

	// Sanity check
	if ((p_hlen >= 0) && (p_hlen < p_blen * 2)) {
    return NULL;
  }

	b = (const uint8_t*)p_bin;
	e = b + p_blen - 1;
	s = p_hex + p_blen * 2;
	if (s < p_hex + p_hlen) *s = 0;
	for (; b <= e; e--) {
		*(--s) = _hexDigits[(*e) & 0xF];
		*(--s) = _hexDigits[(*e) >> 4];
	}
	return p_hex + p_blen * 2;
}

void usage(const char* p_progname, const uint8_t p_role) {
  if ((p_role == 0) || (p_role == 1)) {
    fprintf(stderr, "Usage: %s -a<UDP protocol> -i<NIC ITS> -m<mac_address> -n<NIC ITS> -p<udp_port> -u<udp_address> [-d] [-hv]\n", p_progname);
    fprintf(stderr, "E.g.: %s -amulticast -m024294b76804 -neth1 -p5000 -u239.168.1.100 -d\n", p_progname);
    fprintf(stderr, "E.g.: %s -c ~/ets/my_config.cfg\n", p_progname);
    if (p_role == 0) { /* its_bridge_client */
      fprintf(
              stderr,
              "%s captures ITS messages and send them embedded an UDP packet\n"
              "\t-a: UDP protocol (broacast or multticast and unicast if not present)\n"
              "\t-c: Use configuration file instead of command line argumens\n"
              "\t-d: Daemon mode\n"
              "\t-i: Network Interface Card name for UDP\n"
              "\t-m: MAC address of the ITS interface\n"
              "\t-n: Network Interface Card name for ITS capture\n"
              "\t-p: UDP destination port\n"
              "\t-u: UDP address (broadcast, multicast or remote address)\n"
              "\t-h|-v: Help\n",
              p_progname
              );
    } else {
      fprintf(
              stderr,
              "%s injects ITS messages received in UDP broadcasted messages\n"
              "\t-a: UDP protocol (broacast or multticast and unicast if not present)\n"
              "\t-c: Use configuration file instead of command line argumens\n"
              "\t-d: Daemon mode\n"
              "\t-i: Network Interface Card name for UDP\n"
              "\t-m: MAC address of the ITS interface\n"
              "\t-n: Network Interface Card name for ITS capture\n"
              "\t-p: UDP destination port\n"
              "\t-u: UDP address (broadcast, multicast or remote address)\n"
              "\t-h|-v: Help\n",
              p_progname
              );
    }
  } else {
    fprintf(stderr, "Usage: %s -c<configuration file> [-d] [-hv]\n", p_progname);
    fprintf(stderr, "E.g.: %s -c ~/ets/my_webserver_config.cfg -d\n", p_progname);
  }

  return;
}

int32_t set_pid_file(const char* p_pid_file) {
  int32_t fd = open(p_pid_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  char str[10];

  if (fd < 0) {
    fprintf(stderr, "Can't create PID file \"%s\": %s.\n", p_pid_file, strerror (errno));
    return -1;
  }
  sprintf(str, "%d", getpid());
	write(fd, str, strlen(str));
  close(fd);

  return 0;
}

char* get_pid_from_file(const char* p_pid_file) {
  return load_file(p_pid_file);
}

int32_t set_lock_file(const char* p_lock_file) {
  int32_t fd = open(p_lock_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  char str[10];

  if (fd < 0) {
    fprintf(stderr, "Can't create PID file \"%s\": %s.\n", p_lock_file, strerror (errno));
    return -1;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    fprintf(stderr, "Can't lock the lock file \"%s\". Is another instance running?\n", p_lock_file);
    exit(-1);
  }
  sprintf(str, "%d", getpid());
	write(fd, str, strlen(str));

  return fd;
}

void set_sigaction_signal(const int32_t p_signal, sigaction_signal_callback p_sigaction_handler) {
  static struct sigaction sigact;

  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = p_sigaction_handler;
  sigact.sa_flags = SA_SIGINFO;
  sigaction(p_signal, &sigact, NULL);
}

void daemonize() {
  int32_t i, lfp;

	if (getppid() == 1) {
    return; /* Already a daemon */
  }

	i = fork();
	if (i < 0) {
    fprintf(stderr, "daemonize: 'fork' operation failure: %s.\n", strerror(errno));
    exit(-1);
  }
	if (i > 0) {
    printf("daemonize: 'fork' operation failure: parent exists.\n");
    exit(0);
  }

	/* Child (daemon) continues */
	setsid(); /* Obtain a new process group */
	for (i = getdtablesize();i >= 0; --i) { /* Close all descriptors */
    close(i);
  }

	i = open("/dev/null", O_RDWR); /* Redirection of standards outputs */
  dup(i); dup(i);

	umask(027); /* Set newly created file permissions */

  /* Ignore part of signals */
  signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);

  return;
}

char* string_to_base64 (const char *p_message) {
  const char *lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned long l;
  size_t i;
  char *tmp;
  size_t length = strlen (p_message);

  tmp = malloc (length * 2 + 1);
  if (NULL == tmp)
    return NULL;
  tmp[0] = 0;
  for (i = 0; i < length; i += 3)
    {
      l = (((unsigned long) p_message[i]) << 16)
        | (((i + 1) < length) ? (((unsigned long) p_message[i + 1]) << 8) : 0)
        | (((i + 2) < length) ? ((unsigned long) p_message[i + 2]) : 0);


      strncat (tmp, &lookup[(l >> 18) & 0x3F], 1);
      strncat (tmp, &lookup[(l >> 12) & 0x3F], 1);

      if (i + 1 < length)
        strncat (tmp, &lookup[(l >> 6) & 0x3F], 1);
      if (i + 2 < length)
        strncat (tmp, &lookup[l & 0x3F], 1);
    }

  if (length % 3)
    strncat (tmp, "===", 3 - length % 3);

  return tmp;
}

long get_file_size(const char *p_filename) {
  FILE* fp = fopen (p_filename, "rb");
  if(fp != NULL) {
    size_t size;
    if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp)))) {
      size = 0;
    }
    fclose (fp);
    return size;
  }

  return 0;
}

char* load_file (const char *p_filename) {
  size_t size = get_file_size (p_filename);
  if (size == 0) {
    return NULL;
  }

  FILE* fp = fopen (p_filename, "rb");
  if (fp == NULL) {
    return NULL;
  }

  char* buffer = malloc(size + 1);
  if (buffer == NULL) {
    fclose (fp);
    return NULL;
  }
  buffer[size] = '\0';

  if ((long)fread (buffer, 1, size, fp) != size) {
    free (buffer);
    buffer = NULL;
  }

  fclose (fp);
  return buffer;
}

int32_t load_binary_file(const char *p_filename, uint8_t** p_buffer, size_t* p_size) {
  printf(">>> load_binary_file: %s.\n", p_filename);

  *p_size = get_file_size(p_filename);
  if (*p_size == 0) {
    fprintf(stderr, "load_binary_file: Invalid size.\n");
    return -1;
  }
  printf("load_binary_file: size=%lu.\n", *p_size);
  FILE* fp = fopen(p_filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "load_binary_file: Failed to open file: %s.\n", strerror(errno));
    return -1;
  }
  *p_buffer = malloc(*p_size);
  if (*p_buffer == NULL) {
    fprintf(stderr, "load_binary_file: Failed to allocate memory: %s.\n", strerror(errno));
    fclose(fp);
    return -1;
  }
  if (*p_size != (size_t)fread(*p_buffer, 1, *p_size, fp)) {
    fprintf(stderr, "load_binary_file: Failed to read file: %s.\n", strerror(errno));
    free(*p_buffer);
    *p_buffer = NULL;
    return -1;
  }

  fclose (fp);

  printf("<<< load_binary_file: Before read.\n");
  return 0;
}

int32_t save_configuration_file(const char *p_filename, const char* progname, ...) {
  printf(">>> save_configuration_file: %s, %s.\n", p_filename, progname);

  FILE* fp = fopen(p_filename, "w"); /* Open and erase content */
  if (fp == NULL) {
    return -1;
  }

  va_list va;
  va_start(va, progname);

  int32_t opt;
  while ((opt = (int32_t)va_arg(va, int32_t)) != -1) {
    
  } /* End of 'while' statement */
  //TODO parse_options_va (daemon, &servaddr, va);

  printf("save_configuration_file: its_nic:%s/%s, IP:%s:%s:%d.\n", its_nic, mac_address, udp_nic, udp_address, udp_port);

  fprintf(fp, "# %s.conf sample\n", "client");
  fprintf(fp, "daemon_mode=%d\n", 0);
  fprintf(fp, "mac_address=%s\n", mac_address);
  fprintf(fp, "its_nic=%s\n", its_nic);
  fprintf(fp, "udp_nic=%s\n", udp_nic);
  fprintf(fp, "udp_address=%s\n", udp_address);
  fprintf(fp, "udp_protocol=multicast\n");
  fprintf(fp, "udp_port=%d\n", udp_port);
  fclose(fp);

  va_end(va);

  return 0;
}

char** str_split(const char* p_string, const char p_separator) {
  printf(">> str_split: %s - %c\n", p_string, p_separator);

  /* Count how many elements will be extracted */
  size_t count = 0;
  char* current = (char*)p_string;
  char* previous = NULL;
  while (*current != 0x00) {
    if (p_separator == *current) {
      count++;
      previous = current;
    }
    current++;
  }
  /* Add space for trailing token */
  count += previous < (p_string + strlen(p_string) - 1);
  /* Add space for terminating null string */
  count++;

  char delim[2];
  sprintf(delim, "%c", p_separator);
  char** result = malloc(count * sizeof(char*));
  if (result == NULL) {
    fprintf(stderr, "str_split: %s.\n", strerror(errno));
    return NULL;
  }

  size_t idx  = 0;
  char* cp = strdup(p_string);
  char* token = strtok(cp, delim);
  while (token != NULL) {
    *(result + idx++) = strdup(token);
    token = strtok(NULL, delim);
  }
  *(result + idx) = 0;
  free(cp);

  printf("<<< %p.\n", result);
  return result;
}
