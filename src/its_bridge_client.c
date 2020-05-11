/**
   \Brief 
*/

#include "its_bridge_client.h"
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

pcap_t* device = NULL;
int32_t socket_hd = -1;
struct sockaddr_in remote_addr = {0};

#define PID_FILE_NAME  "/var/run/its_bridge_client.pid"
#define LOCK_FILE_NAME "/var/run/its_bridge_client.lock"

void sig_handler(int p_signal) {
  printf(">>> sig_handler: signal=%d.\n", p_signal);
  state = _exiting;
  pcap_breakloop(device);
  pcap_close(device);
  device = NULL;
}

void sig_usr1_handler(int p_signal) {
  printf(">>> sig_usr1_handler: Reload confguration file.\n");
  state = _reload;
  pcap_breakloop(device);
  pcap_close(device);
  device = NULL;
}

void pcap_message_callback(u_char* p_args, const struct pcap_pkthdr* p_pkthdr, const u_char* p_packet) {
  if (sendto(socket_hd, p_packet, p_pkthdr->caplen, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
    fprintf(stderr, "pcap_message_callback: 'sento' failure: %s, continue.\n", strerror(errno));
  }
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
    usage(p_argv[0], 0);
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
    goto error;
  }
  if (mac_address == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: MAC address of the OBU missing, exit.\n");
    goto error;
  }
  if (udp_nic == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: UDP NIC missing, exit.\n");
    goto error;
  }
  if (udp_address == NULL) {
    fprintf(stderr, "Failed to parse command line arguments: UDP broadcast address missing, exit.\n");
    goto error;
  }
  if ((udp_protocol != NULL) && (strcmp(udp_protocol, "broadcast") != 0) && (strcmp(udp_protocol, "multicast") != 0)) {
    fprintf(stderr, "Failed to parse command line arguments: UDP protocol: broadcast or multicast required and omitted for unicast, exit.\n");
    goto error;
  }
  if (udp_port == 0) {
    fprintf(stderr, "Failed to parse command line arguments: UDP broadcast udp_port missing, exit.\n");
    goto error;
  }
  printf("its_nic:%s/%s, IP:%s:%s:%d, %s, daemonized:%x.\n", its_nic, mac_address, udp_nic, udp_address, udp_port, (udp_protocol == NULL) ? "unicast" : udp_protocol, daemonized);

  /* Daemonize */
  if (daemonized == true) {
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
    /* Prepare UDP broadcast socket to transfer ITS traffic throught router level 3 */
    if ((socket_hd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      fprintf(stderr, "Failed to create UDP socket: %s.\n", strerror(errno));
      goto error;
    }
    /* Bind it to the specified NIC Ethernet */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", udp_nic);
#ifndef __APPLE__
    if (setsockopt(socket_hd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr.ifr_name, strlen(ifr.ifr_name)) < 0) {
      fprintf(stderr, "Failed to set option SO_BINDTODEVICE:%s.\n", strerror(errno));
      shutdown(socket_hd, 2);
      close(socket_hd);
      goto error;
    }
    printf("Bound to device %s.\n", ifr.ifr_name);
#endif
    /* Configure the udp_port and ip we want to send to */
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
          fprintf(stderr, "Failed to get interface address: %s.\n", strerror(errno));
          close(socket_hd);
          goto error;
        }
        printf("Interface address for %s: %s\n", ifr.ifr_name, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
        /* Set local interface for outbound multicast datagrams */
        struct in_addr addr;
        addr.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
        if(setsockopt(socket_hd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&addr, sizeof(addr)) < 0) {
          fprintf(stderr, "Failed to set IP_MULTICAST_IF option: %s.\n", strerror(errno));
          close(socket_hd);
          goto error;
        }
        int32_t ttl = 16; // FIXME Use a parameter
        if (setsockopt(socket_hd, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) < 0) {
          fprintf(stderr, "Failed to set IP_MULTICAST_TTL option: %s.\n", strerror(errno));
          close(socket_hd);
          goto error;
        }
      }
    } else { /* Unicast */
      /* Nothing to do */
    }
    memset((void*)&remote_addr, 0x00, sizeof(struct sockaddr_in));
    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, udp_address, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(udp_port);

    /* Prepare ITS traffic capture */
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(its_nic, &net, &mask, error_buffer) != 0) {
      fprintf(stderr, "Failed to fetch newtork address for device %s.\n", its_nic);
      close(socket_hd);
      goto error;
    }
    printf("Device %s Network address: %d.\n", its_nic, net);
    device = pcap_open_live(its_nic, 65535/*64*1024*/, 1, 100, error_buffer);
    if (device == NULL) {
      fprintf(stderr, "Failed to open device %s.\n", its_nic);
      close(socket_hd);
      goto error;
    }
    /* Setup filter */
    char filter[128] = {0};
    char* mac_bc = "ffffffffffff";
    /* Accept ITS broadcasted messages */
    printf("mac_bc: %s.\n", mac_bc);
    printf("mac_address: %s.\n", mac_address);
    strcpy(filter, "ether dst ");
    strcat(filter, mac_bc);
    if (strlen(mac_address) != 0) {
      /* Accept ITS messages sent by this component */
      strcat(filter, " and ether src ");
      strcat(filter, mac_address);
    }
    strcat(filter, " and ether proto 0x8947");
    /* Log final PCAP filter */
    printf("Filter: %s.\n", filter);
    {
      struct bpf_program f = {0};
      if (pcap_compile(device, &f, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "Failed to compile PCAP filter.\n");
        pcap_close(device);
        goto error;
      } else {
        if (pcap_setfilter(device, &f) != 0) {
          fprintf(stderr, "Failed to set PCAP filter.\n");
          pcap_close(device);
          goto error;
        }
      }
      pcap_freecode(&f);
    }
    /* Loop on incoming ITS traffic */
    pcap_loop(device, -1, pcap_message_callback, NULL);
    if (device != NULL) {
      pcap_close(device);
    }

    close(socket_hd);

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
  unlink(PID_FILE_NAME);
  unlink(LOCK_FILE_NAME);
  return -1;
}
