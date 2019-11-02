#include <stdlib.h>
#include <error.h>
#include <argp.h>

// ./ipdump [-aedh] [-i ifrname] [-p  protocol]

/* Program documentation. */
static char doc[] =
  "Sniffer w/ RAW SOCKET -- a program sniffs local network traffic, build upon raw socket...\n\
options\
\vYou Need To Have Root Permission to Use Raw Socket!\n";

/* A description of the arguments we accept. */
static char args_doc[] = "[PROTOCOLS...]";

/* Keys for options without short-options. */
#define OPT_PROTOCOLS  1            /* -–protocols */

/* The options we understand. */
static struct argp_option options[] = {
  {"all",  'a', 0,       0, "Log all packets" },
  {"dump",    'd', 0,       0, "Include packet dump" },
  {"ethernet",    'e', 0,       0, "Include ethernet header" },
  {"interface",   'i', "ifname",  0, "Capture packets on ifname" },
  {"port",   'p', "port",  0, "Filter port" },
  // {0,0,0,0, "The following options should be grouped together:" },
  // {"protocols",   1, "arp ip icmp tcp udp",  0, "Analyse these protocols" },
  // {"filters",   1, "ip <IP addr> port <PORT number>",  0, "Filter " },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char **protocols;               /* [string…] */
  // char **filters;               /* [string…] */
  int all, ethernet, dump, port;
  char *interface;            /* file arg to ‘--output’ */
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *args = (struct arguments *)state->input;

  switch (key)
  {
  case 'a':
    args->all = 1;
    break;
  case 'd':
    args->dump = 1;
    break;
  case 'e':
    args->ethernet = 1;
    break;
  case 'i':
    args->interface = arg;
    break;
  case 'p':
    args->port = (unsigned short)(atoi(arg));
    break;
  case ARGP_KEY_ARGS:
    args->protocols = state->argv + state->next;
    state->next = state->argc;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };