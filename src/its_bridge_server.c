/**
 \brief 
 */

#include "its_bridge_server.h"
#include "utils.h"

extern char* its_nic;
extern char* mac_address;
extern char* udp_nic;
extern char* udp_address;
extern char* udp_protocol;
extern char* config_file;
extern uint16_t udp_port;
extern bool daemonized;
extern char* pid_file;
extern state_t state;

bool running = false;
int32_t socket_hd = -1;
size_t num_addresses = -1;
char** udp_addresses = NULL;
struct ip_mreq** mreq = NULL;

#define PID_FILE_NAME  "/var/run/its_bridge_server.pid"
#define LOCK_FILE_NAME "/var/run/its_bridge_server.lock"

#define NUM_BLOCKS      1                 /*! Number of 1Kb blocks */
#define MAX_BUFFER_SIZE NUM_BLOCKS * 1024 /*! Total size */

void sig_handler(int p_signal) {
  printf(">>> sig_handler: signal=%d.\n", p_signal);
  running = false;
  shutdown(socket_hd, SHUT_RDWR);
  close(socket_hd);
  socket_hd = -1;
}

void sig_usr1_handler(int p_signal) {
  printf(">>> sig_usr1_handler: Reload confguration file.\n");
  state = _reload;
}

int main(const int32_t p_argc, char* const p_argv[]) {
  /* Sanity check */
  uid_t uid = getuid();
  if (geteuid() != uid) {
    fprintf(stderr, "Do not authorize setuid, exit.\n");
    return -1;
  }

  /* Check parameter */
  int32_t result = parse_params(p_argc, p_argv);
  if (result < 0) {
    usage(p_argv[0], 1);
    if (result == -1) {
      fprintf(stderr, "Failed to parse command line arguments, exit.\n");
    }
    return result;
  }
  if (config_file != NULL) {
    if (parse_config_file(config_file) == -1) {
      fprintf(stderr, "Failed to parse configuration line, exit.\n");
      return -1;
    }
  }
  if (its_nic == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: NIC ITS of ITS traffic missing, exit.\n");
    return -1;
  }
  if (mac_address == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: MAC address of the OBU missing, exit.\n");
    return -1;
  }
  if (udp_nic == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: NIC UDP missing, exit.\n");
    return -1;
  }
  if (udp_address == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: UDP address missing, exit.\n");
    return -1;
  } else {
    udp_addresses = str_split(udp_address, ';', &num_addresses);
    printf("num_addresses = %ld.\n", num_addresses);
    if (udp_addresses == NULL) {
      fprintf(stderr, "Failed to parse multicqst adresses (%s), exit.\n", udp_address);
      return -1;
    }
  }
  if (udp_port == 0) {
    fprintf(stderr, "Failed to parse command line arguments: UDP port missing, exit.\n");
    return -1;
  }
  printf("its_nic:%s/%s, IP:%s:%s:%d, %s.\n", its_nic, mac_address, udp_nic, udp_address, udp_port, udp_protocol);

  /* Daemonize */
  if (daemonized) {
    daemonize();
  }

  /* Here is either the main process is not deamonized or th echild process if deamonized */
  set_pid_file(PID_FILE_NAME); /* Set PID file */
  set_lock_file(LOCK_FILE_NAME); /* Set lock file */

  state = _running;

  /* Catch signals */
  if (!daemonized) {
    signal(SIGINT, sig_handler); /* [C] */
    signal(SIGHUP, sig_handler); /* Terminal closed */
  } else {
    signal(SIGTERM, sig_handler); /* pkill */
  }
  signal(SIGUSR1, sig_usr1_handler); /* kill -SIGUSR1 <pid> to force configuration file to be re-read */

  while (state != _exiting) {
    /* Prepare ITS traffic for packet injection */
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(its_nic, &net, &mask, error_buffer) != 0) {
      fprintf(stderr, "Failed to fetch newtork address for device %s.\n", its_nic);
      goto error;
    }
    printf("Device %s Network address: %d.\n", its_nic, net);
    pcap_t* device = pcap_open_live(its_nic, 65535/*64*1024*/, 1, 100, error_buffer);
    if (device == NULL) {
      fprintf(stderr, "Failed to open device %s.\n", its_nic);
      goto error;
    }

    /* Create UDP brodcast listener */
    struct ifreq ifr; /* Required for IP_DROP_MEMBERSHIP */
    socket_hd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_hd == -1) {
      fprintf(stderr, "Failed to create UDP socket: %s.\n", strerror(errno));
      goto error;
    }
    /* allow multiple instances to receive copies of the multicast datagrams */
    int32_t flags = 1;
    if (setsockopt(socket_hd, SOL_SOCKET, SO_REUSEADDR, (char *)&flags, sizeof(flags)) < 0) {
      fprintf(stderr, "Failed to set SO_REUSEADDR option: %s.\n", strerror(errno));
      close(socket_hd);
      goto error;
    }
    /* Bind it to the specified NIC Ethernet */
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", udp_nic);
#ifndef __APPLE__
    if (setsockopt(socket_hd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr.ifr_name, strlen(ifr.ifr_name)) < 0) {
      fprintf(stderr, "Failed to bind to interface:%s.\n", strerror(errno));
      close(socket_hd);
      goto error;
    }
    printf("Bound to device %s.\n", ifr.ifr_name);
#endif
    /* Configure the udp_port and ip we want to receive from */
    if (udp_protocol != NULL) {
      if (strcmp(udp_protocol, "broadcast") == 0) {
        int32_t flags = 1;
        if (setsockopt(socket_hd, SOL_SOCKET, SO_BROADCAST, (char*)&flags, sizeof(flags)) < 0) {
          fprintf(stderr, "Failed to set option SO_BROADCAST: %s.\n", strerror(errno));
          close(socket_hd);
          goto error;
        }
      } else if (strcmp(udp_protocol, "multicast") == 0) {
        /* Get interface address */
        if (ioctl(socket_hd, SIOCGIFADDR, &ifr) < 0) {
          fprintf(stderr, "Failed to get interface address for %s.\n", ifr.ifr_name);
          close(socket_hd);
          goto error;
        }
        printf("Interface address for %s: %s\n", ifr.ifr_name, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
        /* Join the multicast group */
	mreq = (struct ip_mreq*)malloc(num_addresses * sizeof(struct ip_mreq*));
	fprintf(stderr, "0000\n");
	memset((void*)mreq, 0x00, num_addresses * sizeof(struct ip_mreq*));
	fprintf(stderr, "1111\n");
	for (size_t i = 0; i < num_addresses; i++) {
	  fprintf(stderr, "2222\n");
	  struct ip_mreq* mr = (struct ip_mreq*)malloc(sizeof(struct ip_mreq));
	  *(mreq + i) = mr;
	  fprintf(stderr, "3333\n");
	  mr->imr_interface.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr)); /* Local address */
	  mr->imr_multiaddr.s_addr = inet_addr(*(udp_addresses + i)); /* IP multicast address of group */
	  printf("mreq.imr_interface.s_addr = %s.\n", inet_ntoa(mr->imr_interface));
	  printf("mreq.imr_multiaddr.s_addr = %s.\n", inet_ntoa(mr->imr_multiaddr));
	  if (setsockopt(socket_hd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)mr, sizeof(struct ip_mreq)) < 0) {
	    fprintf(stderr, "Failed to set option IP_ADD_MEMBERSHIP: %s.\n", strerror(errno));
	    close(socket_hd);
	    goto error;
	  }
	  /* Do not free resource here - free(*(udp_addresses + i)); */
        }
        /* Do not free resource here - free(udp_addresses); */
        int32_t ttl = 16; // FIXME Use a parameter
        if (setsockopt(socket_hd, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) < 0) {
          fprintf(stderr, "Failed to set option IP_MULTICAST_TTL: %s.\n", strerror(errno));
          close(socket_hd);
          goto error;
        }
      }
    } else { /* Unicast */
      /* Nothing to do */
    }
    /* Configure the port and ip we want to send to */
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(udp_port);
    if (bind(socket_hd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      fprintf(stderr, "Failed to bind UDP broadcast socket: %s.\n", strerror(errno));
      close(socket_hd);
      goto error;
    }
    /* Start listening */
    running = true;
    uint8_t buffer[MAX_BUFFER_SIZE];
    int32_t addr_len;
    struct sockaddr_in addr;
    while (running == true) {
      result = recvfrom(socket_hd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addr_len);
      if (result < 0) {
        fprintf(stderr, "'recvfrom' operation failure: %s, stay in loop.\n", strerror(errno));
        continue;
      }
      printf("Received UDP broadcast:%s:%u.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
      // Inject the packet
      struct ether_header* eth_header = (struct ether_header*)buffer;
      char eth_src[10];
      bin2hex(eth_src, 10, (const uint8_t*)(eth_header->ether_shost), 6);
      if (strcmp(eth_src, mac_address) != 0) { /* do not inject our own packet - Should never be the case */
        pcap_sendpacket(device, buffer, result);
      }
    } /* End of 'while' statement */

    pcap_close(device);
    if (socket_hd != -1) {
      if (strcmp(udp_protocol, "multicast") == 0) {
        /* Leave the multicast group */
	for (size_t i = 0; *(udp_addresses + i); i++) {
	  struct ip_mreq* mr = *(mreq + i);
	  if (setsockopt(socket_hd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)mr, sizeof(struct ip_mreq)) < 0) {
	    fprintf(stderr, "Failed to set option IP_DROP_MEMBERSHIP: %s.\n", strerror(errno));
	    continue;
	  }
	  free(*(udp_addresses + i));
	  free(mr);
        }
        free(udp_addresses);
	free(mreq);
      }
      shutdown(socket_hd, SHUT_RDWR);
      close(socket_hd);
      socket_hd = -1;
    }
    if (config_file != NULL) {
      free(its_nic);
      free(mac_address);
      free(udp_nic);
      free(udp_address);
      free(udp_protocol);
    }

    if (state == _reload) {
      if (parse_config_file(config_file) == -1) {
        fprintf(stderr, "Failed to parse configuration line, exit.\n");
        goto error;
      }
      printf("Reloaded config: its_nic:%s/%s, IP:%s:%s:%d, %s.\n", its_nic, mac_address, udp_nic, udp_address, udp_port, (udp_protocol == NULL) ? "unicast" : udp_protocol);

      state = _running;
    }
  } /* End of 'while' statement */

  unlink(PID_FILE_NAME);
  unlink(LOCK_FILE_NAME);

  return 0;

 error:
  for (size_t i = 0; *(udp_addresses + i); i++) {
    free(*(udp_addresses + i));
    if (*(mreq + i) != NULL) {
      free(*(mreq + i));
    }
  }
  free(udp_addresses);
  free(mreq);
  unlink(PID_FILE_NAME);
  unlink(LOCK_FILE_NAME);
  return -1;
}
