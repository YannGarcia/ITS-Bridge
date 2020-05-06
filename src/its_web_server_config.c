/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <microhttpd.h>
#include "utils.h"

extern char* login;
extern char* password;
extern char* realm;
extern char* cert_pem;
extern char* cert_key;
extern uint16_t https_port;
extern char* conf_path;
extern char* config_file;
extern bool daemonized;
extern char* pid_file;
extern state_t state;

extern char* nic_its;
extern char* mac_address;
extern char* udp_address;
extern uint16_t udp_port;

struct connection_info_struct {
  int32_t connectiontype;
  char* url;
  struct MHD_PostProcessor *postprocessor;
};
struct MHD_Daemon* daemon_hd = NULL;

static char* buffer = NULL; /* Shall be static because of asynchronous mode */
#define MAX_PATH_SIZE   256
static char client_config_file[MAX_PATH_SIZE];
static char server_config_file[MAX_PATH_SIZE];

#define PID_FILE_NAME   "/var/run/its_web_server_config.pid"
#define LOCK_FILE_NAME  "/var/run/its_web_server_config.lock"

#define POSTBUFFERSIZE  512
#define MAXVALUESIZE    32
#define GET             0
#define POST            1

void sig_usr1_handler(int p_signal) {
  printf("sig_usr1_handler: Reload confguration file.\n");
  state = _exiting;
  if (daemon_hd != NULL) {
    MHD_stop_daemon(daemon_hd);
    daemon_hd = NULL;
  }
}

static int32_t welcome_page(struct MHD_Connection *p_connection) {
  printf(">>> welcome_page.\n");

  const char* page =
    "<!DOCTYPE html><html><body><h2>ITS Bridge Web Confgurator</h2><p>Welcome page.</p>"
    "<form action=\"/\" method=\"POST\">"
    "<input type=\"button\" onClick=\"location.href='/client_url'\" value=\"Configure ITS_Bridge client\">"
    "<input type=\"button\" onClick=\"location.href='/server_url'\" value=\"Configure ITS_Bridge server\">"
    "<input type=\"button\" onClick=\"location.href='/web_url'\" value=\"Configure ITS_Bridge Web server\">"
    "<input type=\"button\" onClick=\"location.href='/help_url'\" value=\"Help\">"
    "</form></body></html>";

  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void*)(const char*)page, MHD_RESPMEM_PERSISTENT);
  if (response == NULL) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response(p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

static int32_t send_favicon(struct MHD_Connection *p_connection) {
  printf(">>> send_favicon.\n");

  uint8_t* favicon;
  size_t size;
  int32_t result = load_binary_file("../resources/favicon.jpg", &favicon, &size);
  if (result == -1) {
    return MHD_NO;
  }
  if (buffer != NULL) {
    free(buffer);
  }
  buffer = favicon;

  struct MHD_Response *response = MHD_create_response_from_buffer(size, (void*)buffer, MHD_RESPMEM_PERSISTENT);
  if (!response) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response(p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

static int32_t web_client_page(struct MHD_Connection *p_connection) {
  const char* page =
    "<!DOCTYPE html><html><body><h2>ITS Bridge Web Confgurator</h2><p>Please enter ETSI ITS_Bridge_client configuration:</p>"
    "<form action=\"/client_url\" method=\"POST\">"
    "<label for=\"nic_its\">Nic ITS:</label><br>"
    "<input type=\"text\" id=\"nic_its\" name=\"nic_its\" value=\"%s\"><br>"
    "<label for=\"mac_address\">Mac Address:</label><br>"
    "<input type=\"text\" id=\"mac_address\" name=\"mac_address\" value=\"%s\"><br>"
    "<label for=\"udp_address\">Udp Address:</label><br>"
    "<input type=\"text\" id=\"udp_address\" name=\"udp_address\" value=\"%s\"><br>"
    "<label for=\"https_port\">Udp Port:</label><br>"
    "<input type=\"number\" id=\"udp_port\" name=\"udp_port\" value=\"%d\"><br><br>"
    "<input type=\"submit\" value=\"Submit\">"
    "<input type=\"reset\">"
    "</form></body></html>";

  if (buffer != NULL) {
    free(buffer);
  }
  size_t size = strlen(page) * 2;
  buffer = (char*)malloc(size);
  memset((void*)buffer, 0x00, size);
  snprintf(buffer, size, page, nic_its, mac_address, udp_address, udp_port);
  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buffer), (void*)(const char*)buffer, MHD_RESPMEM_PERSISTENT);
  if (!response) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response(p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

static int32_t web_server_page(struct MHD_Connection *p_connection) {
  const char* page =
    "<!DOCTYPE html><html><body><h2>ITS Bridge Web Confgurator</h2><p>Cient page.</p>"
    "</form></body></html>";

  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void*)(const char*)page, MHD_RESPMEM_PERSISTENT);
  if (!response) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response(p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

static int32_t web_help_page(struct MHD_Connection *p_connection) {
  printf(">>> web_help_page.\n");

  const char* page =
    "<!DOCTYPE html><html><body><h2>ITS Bridge Web Confgurator</h2><p>Help page.</p>"
    "</form></body></html>";

  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void*)(const char*)page, MHD_RESPMEM_PERSISTENT);
  if (!response) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response (p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

static int32_t web_config_page(struct MHD_Connection *p_connection) {
  printf(">>> web_config_page.\n");

  const char* page =
    "<!DOCTYPE html><html><body><h2>ITS Bridge Web Confgurator</h2><p>Please enter ETSI ITS_Bridge webserver configuration:</p>"
    "<form action=\"/web_config\" method=\"POST\">"
    "<label for=\"realm\">Realm:</label><br>"
    "<input type=\"text\" id=\"realm\" name=\"realm\" value=\"%s\"><br>"
    "<label for=\"login\">Login:</label><br>"
    "<input type=\"text\" id=\"login\" name=\"login\" value=\"%s\"><br>"
    "<label for=\"pwd\">Password:</label><br>"
    "<input type=\"password\" id=\"pwd\" name=\"pwd\" value=\"%s\"><br>"
    "<label for=\"https_port\">Port:</label><br>"
    "<input type=\"number\" id=\"port\" name=\"port\" value=\"%d\"><br><br>"
    "<input type=\"submit\" value=\"Submit\">"
    "<input type=\"reset\">"
    "</form></body></html>";

  if (buffer != NULL) {
    free(buffer);
  }
  size_t size = strlen(page) * 2;
  buffer = (char*)malloc(size);
  memset((void*)buffer, 0x00, size);
  snprintf(buffer, size, page, realm, login, password, https_port);
  struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buffer), (void*)(const char*)buffer, MHD_RESPMEM_PERSISTENT);
  if (response == NULL) {
    return MHD_NO;
  }

  int32_t ret = MHD_queue_response (p_connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

static int32_t ask_for_authentication(struct MHD_Connection *connection, const char *realm) {
  int32_t ret;
  struct MHD_Response *response;
  char *headervalue;
  size_t slen;
  const char *strbase = "Basic realm=";

  response = MHD_create_response_from_buffer (0, NULL,
                                              MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;

  slen = strlen(strbase) + strlen(realm) + 1;
  if (NULL == (headervalue = malloc(slen)))
    return MHD_NO;
  snprintf(headervalue,
           slen,
           "%s%s",
           strbase,
           realm);
  ret = MHD_add_response_header(response,
                                "WWW-Authenticate",
                                headervalue);
  free(headervalue);
  if (! ret)
    {
      MHD_destroy_response(response);
      return MHD_NO;
    }

  ret = MHD_queue_response(connection,
                           MHD_HTTP_UNAUTHORIZED,
                           response);
  MHD_destroy_response(response);
  return ret;
}

static int32_t is_authenticated(struct MHD_Connection *connection, const char *username, const char *password) {
  const char *headervalue;
  char *expected_b64;
  char *expected;
  const char *strbase = "Basic ";
  int32_t authenticated;
  size_t slen;

  headervalue = MHD_lookup_connection_value (connection, MHD_HEADER_KIND, "Authorization");
  if (NULL == headervalue)
    return 0;
  if (0 != strncmp (headervalue, strbase, strlen (strbase)))
    return 0;

  slen = strlen (username) + 1 + strlen (password) + 1;
  if (NULL == (expected = malloc (slen)))
    return 0;
  snprintf (expected,
            slen,
            "%s:%s",
            username,
            password);
  expected_b64 = string_to_base64 (expected);
  free (expected);
  if (NULL == expected_b64)
    return 0;

  authenticated =
    (strcmp (headervalue + strlen (strbase), expected_b64) == 0);
  free (expected_b64);
  return authenticated;
}

static int32_t post_iterator(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                             const char *filename, const char *content_type,
                             const char *transfer_encoding, const char *data, uint64_t off,
                             size_t size) {
  (void) kind;               /* Unused. Silent compiler warning. */
  (void) filename;           /* Unused. Silent compiler warning. */
  (void) content_type;       /* Unused. Silent compiler warning. */
  (void) transfer_encoding;  /* Unused. Silent compiler warning. */
  (void) off;                /* Unused. Silent compiler warning. */
  struct connection_info_struct *con_info = coninfo_cls;

  printf(">>> post_iterator: %s:%s - %s.\n", key, data, con_info->url);

  if (strcmp(con_info->url, "/client_url") == 0) {
    if (strcmp (key, "nic_its") == 0) {
      if (nic_its != NULL) {
        free(nic_its);
      }
      nic_its = strdup(data);
    } else if (strcmp (key, "mac_address") == 0) {
      if (mac_address != NULL) {
        free(mac_address);
      }
      mac_address = strdup(data);
    } else if (strcmp (key, "udp_address") == 0) {
      if (udp_address != NULL) {
        free(udp_address);
      }
      udp_address = strdup(data);
    } else if (strcmp (key, "udp_port") == 0) {
      udp_port = atoi(data);
    }
  } else if (strcmp(con_info->url, "/server_url") == 0) {
  } else {
  }

  return MHD_YES;
}

static int32_t answer_to_connection (void *cls, struct MHD_Connection *connection,
                                 const char *url, const char *method,
                                 const char *version, const char *upload_data,
                                 size_t *upload_data_size, void **con_cls)
{
  (void)cls;               /* Unused. Silent compiler warning. */
  (void)version;           /* Unused. Silent compiler warning. */

  printf(">>> answer_to_connection: %s, %s.\n", method, url);

  /* First time (*con_cls == NULL), return success */
  if (*con_cls == NULL) {
    if (buffer != NULL) {
      free(buffer);
      buffer = NULL;
    }
    struct connection_info_struct *con_info = malloc (sizeof (struct connection_info_struct));
    if (con_info == NULL) {
      fprintf(stderr, "answer_to_connection: Failed to allocate memory:%s.\n", strerror(errno));
      return MHD_NO;
    }
    /* Check HTTP method */
    if (strcmp(method, "POST") == 0) {
      /* Process POST */
      con_info->postprocessor = MHD_create_post_processor(connection, POSTBUFFERSIZE, post_iterator, (void*)con_info);
      if (con_info->postprocessor == NULL) {
        fprintf(stderr, "answer_to_connection: Failed to prepare HTTP POST processing.\n");
        free(con_info);
        return MHD_NO;
      }
      con_info->connectiontype = POST;
    } else if (strcmp(method, "GET") == 0) {
      con_info->connectiontype = GET;
    } else {
      fprintf(stderr, "answer_to_connection: Unsupported HTTP method.\n");
      free(con_info);
      return MHD_NO;
    }

    con_info->url = strdup(url);
    *con_cls = (void*)con_info;

    return MHD_YES;
  }
  /* This is not the first time! */

  /* Check authentication */
  if (!is_authenticated (connection, login, password)) {
    return ask_for_authentication (connection, realm);
  }

  /* Process HTTP method */
  if (strcmp(method, "POST") == 0) {
    struct connection_info_struct* con_info = *con_cls;
    if (*upload_data_size != 0) { /* Still some data to download */
      MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
      *upload_data_size = 0; /* Reset the data size for next time */
      return MHD_YES;
    } else {
      return welcome_page(connection);
    }
  } else if (strcmp(method, "GET") == 0) {
    /* Check URL */
    if (strncmp(url, "/.", strlen(url)) == 0) {
      return welcome_page(connection);
    } else if (strncmp(url, "/favicon.ico", strlen(url)) == 0) {
      return send_favicon(connection);
    } else if (strncmp(url, "/web_url", strlen(url)) == 0) {
      return web_config_page(connection);
    } else if (strncmp(url, "/client_url", strlen(url)) == 0) {
      return web_client_page(connection);
    } else if (strncmp(url, "/server_url", strlen(url)) == 0) {
      return web_server_page(connection);
    } else {
      return web_help_page(connection);
    }
  } else {
    fprintf(stderr, "answer_to_connection: Unsupported HTTP method.\n");
  }

  return web_help_page(connection);
}

static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls, enum MHD_RequestTerminationCode rtc) {
  (void) cls;         /* Unused. Silent compiler warning. */
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) rtc;         /* Unused. Silent compiler warning. */

  struct connection_info_struct* con_info = *con_cls;

  printf("request_completed: %s.\n", con_info->url);

  if (con_cls == NULL) {
    return;
  }

  if (con_info->connectiontype == POST) {
    MHD_destroy_post_processor(con_info->postprocessor);
    if (strcmp(con_info->url, "/client_url") == 0) {
      printf("request_completed: Update client.conf.\n");
      /* Create a new one */
      //save_configuration_file(client_config_file, "client", daemon_mode, 0, "mac_address", mac_address, "nic_its", nic_its, "udp_address", udp_address, "udp_protocol", "multicast", "udp_port", udp_port, -1);
      {
        printf("save_configuration_file: nic_its:%s/%s, IP:%s:%d.\n", nic_its, mac_address, udp_address, udp_port);
        FILE* fp = fopen(client_config_file, "w");
        if (fp == NULL) {
          goto end;
        }
        fprintf(fp, "# %s.conf sample\n", "client");
        fprintf(fp, "daemon_mode=%d\n", 0);
        fprintf(fp, "mac_address=%s\n", mac_address);
        fprintf(fp, "nic_its=%s\n", nic_its);
        fprintf(fp, "udp_address=%s\n", udp_address);
        fprintf(fp, "udp_protocol=multicast\n");
        fprintf(fp, "udp_port=%d\n", udp_port);
        fclose(fp);
      }
      /* Load ITS_Bridge_client pid file */
      char* client_pid = get_pid_from_file("/var/run/its_bridge_client.pid");
      printf("Client pid: %s.\n", client_pid);
      if (client_pid != NULL) {
        if (kill((pid_t)atol(client_pid), SIGUSR1) != 0) {
          fprintf(stderr, "request_completed: Failed to signal its_bridge_client process: %s.\n", strerror(errno));
        }
        free(client_pid);
      }
    } else if (strcmp(con_info->url, "/server_url") == 0) {
      printf("request_completed: Update server.conf.\n");
      /* Create a new one */
      //save_configuration_file(server_config_file);
      {
        FILE* fp = fopen(client_config_file, "w");
        if (fp == NULL) {
          goto end;
        }
        fprintf(fp, "# serber.conf sample\n");
        fprintf(fp, "daemon_mode=%d\n", 0);
        fprintf(fp, "mac_address=%s\n", mac_address);
        fprintf(fp, "nic_its=%s\n", nic_its);
        fprintf(fp, "udp_address=%s\n", udp_address);
        fprintf(fp, "udp_protocol=multicast\n");
        fprintf(fp, "udp_port=%d\n", udp_port);
        fclose(fp);
      }
      /* Load ITS_Bridge_server pid file */
      char* server_pid = get_pid_from_file("/var/run/its_bridge_server.pid");
      printf("Server pid: %s.\n", server_pid);
      if (server_pid != NULL) {
        if (kill((pid_t)atol(server_pid), SIGUSR1) != 0) {
          fprintf(stderr, "request_completed: Failed to signal its_bridge_server process: %s.\n", strerror(errno));
        }
        free(server_pid);
      }
    }
  }
end:
  free(con_info->url);

  free(con_info);
  *con_cls = NULL;
}

int32_t main(const int32_t p_argc, char* const p_argv[]) {

  /* Sanity check */
  uid_t uid = getuid();
  if (geteuid() != uid) {
    fprintf(stderr, "Do not authorize setuid, exit.\n");
    return -1;
  }

  /* Check parameters */
  int32_t result = parse_params(p_argc, p_argv);
  if (result < 0) {
    usage(p_argv[0], 3);
    if (result == -1) {
      fprintf(stderr, "Failed to parse command line arguments, exit.\n");
    }
    return result;
  }
  if (config_file == NULL) {
    fprintf(stderr, "Failed to retrieve the configuration file, exit.\n");
    return -1;
  }
  if (parse_config_file(config_file) == -1) {
    fprintf(stderr, "Failed to parse configuration file, exit.\n");
    return -1;
  }
  if (login == NULL) {
    fprintf(stderr, "Failed to parse configuration file: login missing, exit.\n");
    goto error;
  }
  if (password == NULL) {
    fprintf(stderr, "Failed to parse configuration file: password missing, exit.\n");
    goto error;
  }
  if (realm == NULL) {
    fprintf(stderr, "Failed to parse configuration file: realm, exit.\n");
    goto error;
  }
  if (cert_pem == NULL) {
    fprintf(stderr, "Failed to parse configuration file: cert_pem missing, exit.\n");
    goto error;
  }
  if (cert_key == NULL) {
    fprintf(stderr, "Failed to parse configuration file: cert_key missing, exit.\n");
    goto error;
  }
  if (conf_path == NULL) {
    fprintf(stderr, "Failed to parse configuration file: conf_path missing, exit.\n");
    goto error;
  }
  printf("realm=%s, login=%s:%s, pem=%s, key=%s, conf_path=%s.\n", realm, login, password, cert_pem, cert_key, conf_path);

  /* Load ITS_Bridge_client configuration file */
  sprintf(client_config_file, "%s/client.conf", conf_path);
  printf("Parsing file %s.\n", client_config_file);
  if (parse_config_file(client_config_file) == -1) {
    fprintf(stderr, "Failed to parse configuration file %s, exit.\n", config_file);
    goto error;
  }
  printf("nic_its:%s/%s, IP:%s:%d.\n", nic_its, mac_address, udp_address, udp_port);
  /* Load ITS_Bridge_server configuration file */

  /* Daemonize */
  if (daemonized) {
    daemonize();
  }

  /* Here is either the main process is not deamonized or th echild process if deamonized */
  set_pid_file(PID_FILE_NAME); /* Set PID file */
  set_lock_file(LOCK_FILE_NAME); /* Set lock file */

  state = _running;

  /* Catch signals */
  signal(SIGUSR1, sig_usr1_handler); /* kill -SIGUSR1 <pid> to force configuration file to be re-read */

  while (state != _exiting) {

    /* Load certificates */
    char* _cert_key = load_file(cert_key);
    char* _cert_pem = load_file(cert_pem);
    if ((_cert_key == NULL) || (_cert_pem == NULL)) {
      printf ("The key/certificate files could not be read.\n");
      if (_cert_key != NULL) {
        free (_cert_key);
      }
      if (_cert_pem != NULL) {
        free (_cert_pem);
      }
      goto error;
    }

    daemon_hd = MHD_start_daemon(
                                 MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS,
                                 https_port,
                                 NULL,
                                 NULL,
                                 &answer_to_connection,
                                 NULL,
                                 MHD_OPTION_NOTIFY_COMPLETED, request_completed,
                                 NULL,
                                 MHD_OPTION_HTTPS_MEM_KEY, _cert_key,
                                 MHD_OPTION_HTTPS_MEM_CERT, _cert_pem, MHD_OPTION_END);
    if (daemon_hd == NULL) {
      printf ("%s\n", _cert_pem);
      free (_cert_key);
      free (_cert_pem);
      goto error;
    }

    fgetc(stdin);
    if (daemon_hd != NULL) {
      MHD_stop_daemon(daemon_hd);
    }

    if (buffer != NULL) {
      free(buffer);
    }

    if (config_file != NULL) {
      free(_cert_key);
      free(_cert_pem);
      free(login);
      free(password);
      free(realm);
      free(cert_pem);
      free(cert_key);
    }

    free(nic_its);
    free(mac_address);
    free(udp_address);

    if (state == _reload) {
      if (parse_config_file(config_file) == -1) {
        fprintf(stderr, "Failed to parse comfiguration line, exit.\n");
        goto error;
      }
      printf("Reloaded config: realm=%s, login=%s:%s, pem=%s, key=%s.\n", realm, login, password, cert_pem, cert_key);
      state = _running;
    }
  } /* End of 'while' statement */

  return 0;
 error:
  if (buffer != NULL) {
    free(buffer);
  }

  return -1;
}
