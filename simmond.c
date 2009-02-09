

/*
 *
 * Network Packet Collector
 *
 * Thu Oct 30 12:18:18 CET 2003 by jarek
 *
 */


/*
 *
 * TODO:
 *
 * - support for other then EN10MB devices (already done PPP)
 * - fast "fixed size" memory allocator (do not use slow libc malloc/free routines)
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <pcap.h>


/* Linux defs to conform to BSD api */
#define __USE_BSD 1
#define __FAVOR_BSD 1

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


/* Make "long long" type portable */
#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) __bswap_64(x)
#define ntohll(x) __bswap_64(x)
#endif
#endif


/* Hardcoded maximum number of collected ranges */
#define MAX_RANGES 256


struct __range
{
  int proto;
  int start_port;
  int stop_port;
  long long remote_input_packets;
  long long remote_input_bytes;
  long long remote_output_packets;
  long long remote_output_bytes;
  long long local_input_packets;
  long long local_input_bytes;
  long long local_output_packets;
  long long local_output_bytes;
};

typedef struct __range range;


struct __stat
{
  int ranges_size;
  long long tcp_input_packets;
  long long tcp_input_bytes;
  long long tcp_output_packets;
  long long tcp_output_bytes;
  long long udp_input_packets;
  long long udp_input_bytes;
  long long udp_output_packets;
  long long udp_output_bytes;
  long long icmp_input_packets;
  long long icmp_input_bytes;
  long long icmp_output_packets;
  long long icmp_output_bytes;
  long long other_input_packets;
  long long other_input_bytes;
  long long other_output_packets;
  long long other_output_bytes;
  range ranges_array[0];
};

typedef struct __stat *stat;


struct __node
{
  void *left;
  void *right;
};

typedef struct __node *node;


typedef int (*handler) (char *);


typedef void (*dumper) (FILE *, stat, unsigned int);


/* Global vars: stats */
static int allocated_nodes = 0;
static int allocated_stats = 0;
static long long total_packets = 0;
static long long total_bytes = 0;
static int work_time = 0;

/* Global vars: file handles and names */
//static FILE *dump_handle = NULL;
static char *dump_binary_name = NULL;
static char *dump_ascii_name = NULL;
static char *dump_stats_name = NULL;

/* Global vars: sniffing params */
static char *device_name = NULL;
static int device_promisc = 0;
static int sniff_count = 0;
static int sniff_limit = 0;
static int sniff_addr = 0;
static int sniff_mask = 0;

/* Global vars: flags */
static int is_processing = 0;
static int dump_binary_request = 0;
static int dump_ascii_request = 0;
static int free_request = 0;
static int dump_packets = 0;

/* Global vars: stat struct pattern for collecting traffic */
static stat pattern = NULL;

/* Global vars: tree root */
static node root = NULL;


void stat_ascii_dump(FILE * f, stat s, unsigned int address)
{
  int i;
  char *prefix;
  struct in_addr buff = { address };
  range *r;

  if(f != NULL && s != NULL)
  {
    fprintf(f,
            "%s tcp:%lld:%lld:%lld:%lld udp:%lld:%lld:%lld:%lld icmp:%lld:%lld:%lld:%lld unknown:%lld:%lld:%lld:%lld",
            inet_ntoa(buff), s->tcp_input_packets, s->tcp_input_bytes, s->tcp_output_packets,
            s->tcp_output_bytes, s->udp_input_packets, s->udp_input_bytes, s->udp_output_packets,
            s->udp_output_bytes, s->icmp_input_packets, s->icmp_input_bytes, s->icmp_output_packets,
            s->icmp_output_bytes, s->other_input_packets, s->other_input_bytes,
            s->other_output_packets, s->other_output_bytes);

    for(i = 0; i < s->ranges_size; i++)
    {
      r = s->ranges_array + i;
      switch (r->proto)
      {
      case IPPROTO_TCP:
        prefix = "tcp";
        break;
      case IPPROTO_UDP:
        prefix = "udp";
        break;
      case IPPROTO_ICMP:
        prefix = "icmp";
        break;
      default:
        prefix = "unknown";
        break;
      }

      fprintf(f, " %s:%d:%d:%lld:%lld:%lld:%lld:%lld:%lld:%lld:%lld",
              prefix, r->start_port, r->stop_port,
              r->remote_input_packets, r->remote_input_bytes, r->remote_output_packets,
              r->remote_output_bytes, r->local_input_packets, r->local_input_bytes,
              r->local_output_packets, r->local_output_bytes);
    }
    fprintf(f, "\n");
  }
}


void stat_binary_dump(FILE * f, stat s, unsigned int address)
{
  int i;
  range *r;

  struct
  {
    int address;
    long long tcp_input_packets;
    long long tcp_input_bytes;
    long long tcp_output_packets;
    long long tcp_output_bytes;
    long long udp_input_packets;
    long long udp_input_bytes;
    long long udp_output_packets;
    long long udp_output_bytes;
    long long icmp_input_packets;
    long long icmp_input_bytes;
    long long icmp_output_packets;
    long long icmp_output_bytes;
    long long other_input_packets;
    long long other_input_bytes;
    long long other_output_packets;
    long long other_output_bytes;
  }
  total_buff;

  struct
  {
    long long remote_input_packets;
    long long remote_input_bytes;
    long long remote_output_packets;
    long long remote_output_bytes;
    long long local_input_packets;
    long long local_input_bytes;
    long long local_output_packets;
    long long local_output_bytes;
  }
  range_buff;

  if(f != NULL && s != NULL)
  {
    total_buff.address = address; /* already in network byte order! */
    total_buff.tcp_input_packets = htonll(s->tcp_input_packets);
    total_buff.tcp_input_bytes = htonll(s->tcp_input_bytes);
    total_buff.tcp_output_packets = htonll(s->tcp_output_packets);
    total_buff.tcp_output_bytes = htonll(s->tcp_output_bytes);
    total_buff.udp_input_packets = htonll(s->udp_input_packets);
    total_buff.udp_input_bytes = htonll(s->udp_input_bytes);
    total_buff.udp_output_packets = htonll(s->udp_output_packets);
    total_buff.udp_output_bytes = htonll(s->udp_output_bytes);
    total_buff.icmp_input_packets = htonll(s->icmp_input_packets);
    total_buff.icmp_input_bytes = htonll(s->icmp_input_bytes);
    total_buff.icmp_output_packets = htonll(s->icmp_output_packets);
    total_buff.icmp_output_bytes = htonll(s->icmp_output_bytes);
    total_buff.other_input_packets = htonll(s->other_input_packets);
    total_buff.other_input_bytes = htonll(s->other_input_bytes);
    total_buff.other_output_packets = htonll(s->other_output_packets);
    total_buff.other_output_bytes = htonll(s->other_output_bytes);

    fwrite(&total_buff, sizeof(total_buff), 1, f);

    for(i = 0; i < s->ranges_size; i++)
    {
      r = s->ranges_array + i;
      range_buff.remote_input_packets = htonll(r->remote_input_packets);
      range_buff.remote_input_bytes = htonll(r->remote_input_bytes);
      range_buff.remote_output_packets = htonll(r->remote_output_packets);
      range_buff.remote_output_bytes = htonll(r->remote_output_bytes);
      range_buff.local_input_packets = htonll(r->local_input_packets);
      range_buff.local_input_bytes = htonll(r->local_input_bytes);
      range_buff.local_output_packets = htonll(r->local_output_packets);
      range_buff.local_output_bytes = htonll(r->local_output_bytes);
      fwrite(&range_buff, sizeof(range_buff), 1, f);
    }
  }
}


/* Traverse binary tree dumping stats kept in leafs */
void node_dump(FILE * f, node root, unsigned int address, unsigned int mask, dumper d)
{
  if(f != NULL && root != NULL)
  {
    if(mask > 1)
    {
      node_dump(f, root->left, address & (~mask), mask >> 1, d);
      node_dump(f, root->right, address | mask, mask >> 1, d);
    }
    else
    {
      if(d != NULL)
      {
        d(f, root->right, address | mask);
        d(f, root->left, address & (~mask));
      }
    }
  }
}


void tree_ascii_dump(node root)
{
  FILE *f;

  if(dump_ascii_name != NULL)
  {
    if((f = fopen(dump_ascii_name, "w+")) != NULL)
    {
      node_dump(f, root, 0, 0x80000000, stat_ascii_dump);;
      fflush(f);
      fclose(f);
    }
  }
  else
  {
    node_dump(stdout, root, 0, 0x80000000, stat_ascii_dump);
    fflush(stdout);
  }

  dump_ascii_request = 0;
}


void header_binary_dump(FILE * f)
{
  int i;

  struct
  {
    int magic;
    int version;
    char device[16];
    int start_time;
    int stop_time;
    int size;
  }
  header_buff;

  struct
  {
    int proto;
    int start_port;
    int stop_port;
  }
  pattern_buff;

  if(f != NULL && pattern != NULL)
  {
    header_buff.magic = htonl(0x31037820);
    header_buff.version = htonl(0x01000000);
    strncpy(header_buff.device, device_name, sizeof(header_buff.device) - 1);
    header_buff.device[sizeof(header_buff.device) - 1] = 0;
    header_buff.start_time = htonl(work_time);
    header_buff.stop_time = htonl(time(NULL));
    header_buff.size = htonl(pattern->ranges_size);

    fwrite(&header_buff, sizeof(header_buff), 1, f);

    for(i = 0; i < pattern->ranges_size; i++)
    {
      pattern_buff.proto = htonl(pattern->ranges_array[i].proto);
      pattern_buff.start_port = htonl(pattern->ranges_array[i].start_port);
      pattern_buff.stop_port = htonl(pattern->ranges_array[i].stop_port);

      fwrite(&pattern_buff, sizeof(pattern_buff), 1, f);
    }
  }
}


void tree_binary_dump(node root)
{
  FILE *f;

  if(dump_binary_name != NULL)
  {
    if((f = fopen(dump_binary_name, "w+")) != NULL)
    {
      header_binary_dump(f);
      node_dump(f, root, 0, 0x80000000, stat_binary_dump);
      fflush(f);
      fclose(f);
    }
  }
  else
  {
    header_binary_dump(stdout);
    node_dump(stdout, root, 0, 0x80000000, stat_binary_dump);
    fflush(stdout);
  }

  dump_binary_request = 0;
}


void __stats_dump(FILE * f)
{
  if(f != NULL)
  {
    fprintf(f, "device: %s\n"
            "packets: %lld\n"
            "bytes: %lld\n"
            "nodes: %d\n"
            "hosts: %d\n"
            "time: %ld\n",
            device_name,
            total_packets, total_bytes, allocated_nodes, allocated_stats, time(NULL) - work_time);
    fflush(f);
  }
}


void stats_dump()
{
  FILE *f;

  if(dump_stats_name != NULL)
  {
    if((f = fopen(dump_stats_name, "w+")) != NULL)
    {
      __stats_dump(f);
      fclose(f);
    }
  }
  else
    __stats_dump(stdout);
}


void packet_dump(FILE * f, int proto, int size, unsigned int src_host, int src_port,
                 unsigned int dst_host, int dst_port)
{
  struct in_addr src_buff = { src_host };
  struct in_addr dst_buff = { dst_host };

  if(f != NULL)
  {
    switch (proto)
    {
    case IPPROTO_TCP:
      fprintf(f, "tcp   %16s : %-5d  > ", inet_ntoa(src_buff), src_port);
      fprintf(f, "%16s : %-5d %5d bytes\n", inet_ntoa(dst_buff), dst_port, size);
      break;
    case IPPROTO_UDP:
      fprintf(f, "udp   %16s : %-5d  > ", inet_ntoa(src_buff), src_port);
      fprintf(f, "%16s : %-5d %5d bytes\n", inet_ntoa(dst_buff), dst_port, size);
      break;
    case IPPROTO_ICMP:
      fprintf(f, "icmp  %16s : %-5d  > ", inet_ntoa(src_buff), src_port);
      fprintf(f, "%16s : %-5d %5d bytes\n", inet_ntoa(dst_buff), dst_port, size);
      break;
    default:
      fprintf(f, "other %16s         > ", inet_ntoa(src_buff));
      fprintf(f, "%16s        %5d bytes\n", inet_ntoa(dst_buff), size);
      break;
    }
  }
}


stat alloc_stat()
{
  stat new_stat;
  int i;

  if(pattern == NULL)
  {
    if((new_stat = (stat) malloc(sizeof(*new_stat))) != NULL)
    {
      memset(new_stat, 0, sizeof(*new_stat));
      allocated_stats++;
    }
  }
  else
  {
    if((new_stat =
        (stat) malloc(sizeof(*new_stat) + (pattern->ranges_size) * sizeof(range))) != NULL)
    {
      memset(new_stat, 0, sizeof(*new_stat) + (pattern->ranges_size) * sizeof(range));
      new_stat->ranges_size = pattern->ranges_size;

      for(i = 0; i < new_stat->ranges_size; i++)
      {
        new_stat->ranges_array[i].proto = pattern->ranges_array[i].proto;
        new_stat->ranges_array[i].start_port = pattern->ranges_array[i].start_port;
        new_stat->ranges_array[i].stop_port = pattern->ranges_array[i].stop_port;
      }
      allocated_stats++;
    }
  }

  return new_stat;
}


void free_stat(stat * s)
{
  if(s != NULL && *s != NULL)
  {
    free(*s);
    *s = NULL;
    allocated_stats--;
  }
}


node alloc_node()
{
  node new_node;

  if((new_node = (node) malloc(sizeof(*new_node))) != NULL)
  {
    new_node->left = NULL;
    new_node->right = NULL;
    allocated_nodes++;
  }

  return new_node;
}


void free_node(node * n)
{
  if(n != NULL && *n != NULL)
  {
    free(*n);
    *n = NULL;
    allocated_nodes--;
  }
}


/* HOTSPOT!!! Traverse binary tree finding given stat - alloc any nodes/leafs if needed */
stat find_stat(node * root, unsigned int address)
{
  unsigned int mask;
  stat *found_stat;

  if(root != NULL)
  {
    for(mask = 0x80000000; mask > 1; mask >>= 1)
    {
      if(*root == NULL && (*root = alloc_node()) == NULL)
        return NULL;
      root = (node *) ((address & mask) ? &((*root)->right) : &((*root)->left));
    }

    if(*root == NULL && (*root = alloc_node()) == NULL)
      return NULL;
    found_stat = (stat *) ((address & mask) ? &((*root)->right) : &((*root)->left));
    if(*found_stat == NULL)
      *found_stat = alloc_stat();

    return *found_stat;
  }

  return NULL;
}


/* Recursive free binary tree node */
void node_free(node * root, unsigned int mask)
{
  if(root != NULL && *root != NULL)
  {
    if(mask > 1)
    {
      node_free((node *) & ((*root)->left), mask >> 1);
      node_free((node *) & ((*root)->right), mask >> 1);
    }
    else
    {
      free_stat((stat *) & ((*root)->right));
      free_stat((stat *) & ((*root)->left));
    }

    free_node(root);
  }
}


/* Free whole binary tree */
void tree_free(node * root)
{
  node_free(root, 0x80000000);
  total_packets = 0;
  total_bytes = 0;
  work_time = time(NULL);
  free_request = 0;
}


/* Handle IP packet frame */
int ip_handler(struct ip *ip_header)
{
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;
  struct icmphdr *icmp_header;

  int i;
  int proto;
  unsigned int src_host;
  unsigned int dst_host;
  int src_port;
  int dst_port;
  int size;
  int flag = 0;
  int result = 0;
  stat s;
  range *r;

  if(ip_header != NULL)
  {
    proto = ip_header->ip_p;
    size = ntohs(ip_header->ip_len) - sizeof(*ip_header);
    src_host = ip_header->ip_src.s_addr;
    src_port = 0;
    dst_host = ip_header->ip_dst.s_addr;
    dst_port = 0;

    switch (proto)
    {
    case IPPROTO_TCP:
      tcp_header = (struct tcphdr *)(ip_header + 1);
      size -= sizeof(*tcp_header);
      src_port = ntohs(tcp_header->th_sport);
      dst_port = ntohs(tcp_header->th_dport);
      break;
    case IPPROTO_UDP:
      udp_header = (struct udphdr *)(ip_header + 1);
      size -= sizeof(*udp_header);
      src_port = ntohs(udp_header->uh_sport);
      dst_port = ntohs(udp_header->uh_dport);
      break;
    case IPPROTO_ICMP:
      icmp_header = (struct icmphdr *)(ip_header + 1);
      size -= sizeof(*icmp_header);
      src_port = dst_port = icmp_header->type;
      break;
    }


    is_processing = 1;

    if((src_host & sniff_mask) == sniff_addr && (s = find_stat(&root, src_host)) != NULL) /* Outgoing 
                                                                                             traffic 
                                                                                           */
    {
      switch (proto)
      {
      case IPPROTO_TCP:
        s->tcp_output_packets++;
        s->tcp_output_bytes += size;
        break;
      case IPPROTO_UDP:
        s->udp_output_packets++;
        s->udp_output_bytes += size;
        break;
      case IPPROTO_ICMP:
        s->icmp_output_packets++;
        s->icmp_output_bytes += size;
        break;
      default:
        s->other_output_packets++;
        s->other_output_bytes += size;
        break;
      }

      for(i = 0, r = s->ranges_array; i < s->ranges_size; i++, r++)
      {
        if(r->proto == proto)
        {
          if(r->start_port <= src_port && r->stop_port >= src_port)
          {
            r->local_output_packets++;
            r->local_output_bytes += size;
          }
          if(r->start_port <= dst_port && r->stop_port >= dst_port)
          {
            r->remote_input_packets++;
            r->remote_input_bytes += size;
          }
        }
      }

      flag = 1;
    }

    if((dst_host & sniff_mask) == sniff_addr && (s = find_stat(&root, dst_host)) != NULL) /* Incoming 
                                                                                             traffic 
                                                                                           */
    {
      switch (proto)
      {
      case IPPROTO_TCP:
        s->tcp_input_packets++;
        s->tcp_input_bytes += size;
        break;
      case IPPROTO_UDP:
        s->udp_input_packets++;
        s->udp_input_bytes += size;
        break;
      case IPPROTO_ICMP:
        s->icmp_input_packets++;
        s->icmp_input_bytes += size;
        break;
      default:
        s->other_input_packets++;
        s->other_input_bytes += size;
        break;
      }

      for(i = 0, r = s->ranges_array; i < s->ranges_size; i++, r++)
      {
        if(r->proto == proto)
        {
          if(r->start_port <= src_port && r->stop_port >= src_port)
          {
            r->remote_output_packets++;
            r->remote_output_bytes += size;
          }
          if(r->start_port <= dst_port && r->stop_port >= dst_port)
          {
            r->local_input_packets++;
            r->local_input_bytes += size;
          }
        }
      }

      flag = 1;
    }

    if(flag)
    {
      sniff_count++;
      if(sniff_limit > 0 && sniff_count >= sniff_limit)
        result = 1;

      total_packets++;
      total_bytes += size;

      if(dump_packets)
        packet_dump(stderr, proto, size, src_host, src_port, dst_host, dst_port);
    }

    if(dump_binary_request)
      tree_binary_dump(root);
    if(dump_ascii_request)
      tree_ascii_dump(root);
    if(free_request)
      tree_free(&root);

    is_processing = 0;
  }

  return result;
}


/* Handle Ethernet packet frame, strip IP frame and pass it alone */
int ethernet_handler(char *packet)
{
  struct ether_header *eth_header;

  if((eth_header = (struct ether_header *)packet) != NULL)
  {
    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
      return ip_handler((struct ip *)(eth_header + 1));
  }

  return 0;
}


/* Handle PPP packet frame, strip IP frame and pass it alone */
int ppp_handler(char *packet)
{
  int proto;

  if(*((unsigned char *)packet) == 0xff && *(packet + 1) == 0x03)
  {
    packet += 2;                /* ACFC not used */
  }

  if(*packet % 2)
  {
    proto = *packet;            /* PFC is used */
    packet++;
  }
  else
  {
    proto = ntohs(*((short *)packet));
    packet++;
    packet++;
  }

  // printf("PPP packet proto :: %04X\n",proto);
  if(proto == 0x0021 || proto == 0x0800)
    return ip_handler((struct ip *)packet);

  return 0;
}


/* Handle SIGUSR1 */
void signal_ascii_dump(int sig)
{
  if(is_processing)
    dump_ascii_request = 1;
  else
    tree_ascii_dump(root);
}


/* Handle SIGUSR2 */
void signal_binary_dump(int sig)
{
  if(is_processing)
    dump_binary_request = 1;
  else
    tree_binary_dump(root);
}


/* Handle SIGINT */
void signal_stats_dump(int sig)
{
  stats_dump();
}


/* Handle SIGHUP */
void signal_free(int sig)
{
  if(is_processing)
    free_request = 1;
  else
    tree_free(&root);
}


/* Handle SIGTERM */
void signal_exit(int sig)
{
  exit(0);
}


int parse_address(char *input, int *addr, int *mask)
{
  char *slash;
  struct in_addr buff;
  char arg[256];
  char char_buff;
  int int_buff;
  int i;

  if(input != NULL && strlen(input) < sizeof(arg) && addr != NULL && mask != NULL)
  {
    strcpy(arg, input);

    if((slash = strchr(arg, '/')) != NULL)
      *slash = 0;
    if(inet_aton(arg, &buff) == 0)
      return -1;

    *addr = buff.s_addr;

    if(slash != NULL)
    {
      if(sscanf(slash + 1, "%d%c", &int_buff, &char_buff) == 1 && int_buff >= 0 && int_buff <= 32)
      {
        *mask = 0;
        for(i = 0; i < int_buff; i++)
          *mask = (*mask >> 1) | 0x80000000;
        *mask = htonl(*mask);
      }
      else
      {
        if(inet_aton(slash + 1, &buff) == 0)
          return -1;
        *mask = buff.s_addr;
      }
    }
    else
      *mask = 0xffffffff;

    return 0;
  }

  return -1;
}


/* Parse command line argument in form: PROTO[:START_PORT[:STOP_PORT]] */
int parse_pattern(char *input, int *proto, int *start_port, int *stop_port)
{
  int i;
  char *first_colon = NULL;
  char *second_colon = NULL;
  char c;
  char arg[256];

  if(input != NULL && strlen(input) < sizeof(arg) && proto != NULL && start_port != NULL
     && stop_port != NULL)
  {
    strcpy(arg, input);

    if((first_colon = strchr(arg, ':')) != NULL)
    {
      *first_colon = 0;
      if((second_colon = strchr(first_colon + 1, ':')) != NULL)
        *second_colon = 0;
    }

    if(strcmp(arg, "tcp") == 0)
      *proto = IPPROTO_TCP;
    else
    {
      if(strcmp(arg, "udp") == 0)
        *proto = IPPROTO_UDP;
      else
      {
        if(strcmp(arg, "icmp") == 0)
          *proto = IPPROTO_ICMP;
        else
          return -1;
      }
    }

    if(first_colon != NULL)
    {
      if(sscanf(first_colon + 1, "%d%c", start_port, &c) != 1)
        return -1;

      if(second_colon != NULL)
      {
        if(sscanf(second_colon + 1, "%d%c", stop_port, &c) != 1)
          return -1;
      }
      else
      {
        *stop_port = *start_port;
      }
    }
    else
    {
      *start_port = 0;
      *stop_port = 0xffff;
    }

    if(*start_port < 0 || *start_port > 0xffff || *stop_port < 0 || *stop_port > 0xffff)
      return -1;

    if(*start_port > *stop_port)
    {
      i = *start_port;
      *start_port = *stop_port;
      *stop_port = i;
    }

    return 0;
  }

  return -1;
}


void usage(char *arg0)
{
  fprintf(stdout,
          "\nUsage:\n\n    %s [-a file] [-b file] [-c limit] [-f filter] [-g group] [-i iface] [-m addr[/mask]] [-p] [-s file] [-u user] [-v] [expression1 [expressionN...]]\n\n",
          arg0);
  fprintf(stdout, "\nOptions:\n\n");
  fprintf(stdout, "   -a file            - ASCII format dump file\n");
  fprintf(stdout, "   -b file            - Binary format dump file\n");
  fprintf(stdout, "   -s file            - Stats dump file (ascii format)\n");
  fprintf(stdout, "   -i iface           - Network interface to listen on (see tcpdump)\n");
  fprintf(stdout, "   -p                 - Set interface to promiscous (see tcpdump)\n");
  fprintf(stdout, "   -v                 - Verbous, print processed packets do stderr\n");
  fprintf(stdout, "   -f filter          - Set captured packets BPF filter (see tcpdump)\n");
  fprintf(stdout, "   -c limit           - Set captured packets limit (see tcpdump)\n");
  fprintf(stdout,
          "   -m ip[/mask]       - Limit collected hosts to given ip. Mask can be in dotted or bits format\n");
  fprintf(stdout, "   -u user            - Set process UID\n");
  fprintf(stdout, "   -g group           - Set process GID\n");
  fprintf(stdout, "\nExpressions:\n\n");
  fprintf(stdout,
          "   Arguments selecting collected traffic are in form PROTOCOL[:START_PORT[:STOP_PORT]].\n");
  fprintf(stdout,
          "   Where protocol may be \"tcp\", \"udp\" and \"icmp\". Start and stop ports are optional.\n");
  fprintf(stdout,
          "   For tcp and udp their meaning is obvious. For icmp they mean icmp message types.\n");
  fprintf(stdout,
          "   If stop port is not specified, it's the same as start port. For example \"tcp:80\" would\n");
  fprintf(stdout,
          "   collect traffic for http protocol, \"tcp:0:1023\" would collect traffic for all low tcp\n");
  fprintf(stdout, "   ports and \"icmp:8\" collects icmp echo request (ping) messages.\n");
  fprintf(stdout,
          "\nExamples:\n\n    %s -i eth0 -b traffic.binary -u nobody -m 192.168.0.0/16 tcp:80 tcp:25 tcp:110 udp:53\n",
          arg0);
  fprintf(stdout,
          "    %s -f 'tcp && ((src net 192.168.0.0/16 && ! dst net 192.168.0.0/16) || (dst net 192.168.0.0/16 && ! src net 192.168.0.0/16))' tcp:80 tcp:25 tcp:110 tcp:0:1024\n\n",
          arg0);
  exit(1);
}


/* Go Kielce! */
int main(int argc, char **argv)
{
  handler phandler = NULL;
  pcap_t *handle = NULL;
  struct pcap_pkthdr header;
  struct bpf_program filter;
  int i, proto, start_port, stop_port, int_buff, addr_buff, mask_buff, link_type;
  int uid = -1, gid = -1;
  char error_buff[PCAP_ERRBUF_SIZE];
  char char_buff;
  char *filter_buff = NULL;
  char *packet;
  struct passwd *pwd;
  struct group *grp;

  if((pattern = (stat) malloc(sizeof(*pattern) + MAX_RANGES * sizeof(range))) == NULL)
    return -1;
  memset(pattern, 0, sizeof(*pattern) + MAX_RANGES * sizeof(range));

  for(i = 1; i < argc; i++)
  {
    if(!parse_pattern(argv[i], &proto, &start_port, &stop_port))
    {
      if(pattern->ranges_size < MAX_RANGES)
      {
        pattern->ranges_array[pattern->ranges_size].proto = proto;
        pattern->ranges_array[pattern->ranges_size].start_port = start_port;
        pattern->ranges_array[pattern->ranges_size].stop_port = stop_port;
        pattern->ranges_size++;
      }
      else
      {
        // Too much pattern ranges
      }
    }
    else
    {
      if(strcmp(argv[i], "-i") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        device_name = argv[++i];
        continue;
      }
      if(strcmp(argv[i], "-a") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        dump_ascii_name = argv[++i];
        continue;
      }
      if(strcmp(argv[i], "-b") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        dump_binary_name = argv[++i];
        continue;
      }
      if(strcmp(argv[i], "-s") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        dump_stats_name = argv[++i];
        continue;
      }
      if(strcmp(argv[i], "-f") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        filter_buff = argv[++i];
        continue;
      }
      if(strcmp(argv[i], "-v") == 0)
      {
        dump_packets = 1;
        continue;
      }
      if(strcmp(argv[i], "-p") == 0)
      {
        device_promisc = 1;
        continue;
      }
      if(strcmp(argv[i], "-c") == 0)
      {
        if(i >= argc - 1 || sscanf(argv[++i], "%d%c", &int_buff, &char_buff) != 1 || int_buff < 0)
          usage(argv[0]);
        sniff_limit = int_buff;
        continue;
      }
      if(strcmp(argv[i], "-m") == 0)
      {
        if(i >= argc - 1 || parse_address(argv[++i], &addr_buff, &mask_buff))
          usage(argv[0]);
        sniff_addr = addr_buff & mask_buff;
        sniff_mask = mask_buff;
        continue;
      }
      if(strcmp(argv[i], "-u") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        i++;
        if((pwd = getpwnam(argv[i])) != NULL)
          uid = pwd->pw_uid;
        else
        {
          if(sscanf(argv[i], "%d%c", &int_buff, &char_buff) != 1)
            usage(argv[0]);
          uid = int_buff;
        }
        continue;
      }
      if(strcmp(argv[i], "-g") == 0)
      {
        if(i >= argc - 1)
          usage(argv[0]);
        i++;
        if((grp = getgrnam(argv[i])) != NULL)
          gid = grp->gr_gid;
        else
        {
          if(sscanf(argv[i], "%d%c", &int_buff, &char_buff) != 1)
            usage(argv[0]);
          gid = int_buff;
        }
        continue;
      }
      usage(argv[0]);
    }
  }

  if(device_name == NULL)
    device_name = pcap_lookupdev(NULL);

  /* Open PCAP device for sniffing and run the main loop */
  if((handle = pcap_open_live(device_name, BUFSIZ, device_promisc, 0, error_buff)) != NULL)
  {
    if(gid >= 0)
      setgid(gid);
    if(uid >= 0)
      setuid(uid);

    /* Apply filter if exists */
    if(filter_buff != NULL)
    {
      if(pcap_compile(handle, &filter, filter_buff, 1, 0) != -1)
        pcap_setfilter(handle, &filter);
      else
        printf("Filter compilation error...\n");
    }

    /* Detect interface type and set proper handler - stolen from tcpdump sources :-) */
    link_type = pcap_datalink(handle);
    if(link_type == DLT_EN10MB)
      phandler = ethernet_handler;
    else if(link_type == DLT_PPP)
      phandler = ppp_handler;
    else if(link_type == DLT_RAW)
      phandler = (handler) ip_handler;

    if(phandler != NULL)
    {
      signal(SIGUSR1, signal_ascii_dump);
      signal(SIGUSR2, signal_binary_dump);
      signal(SIGINT, signal_stats_dump);
      signal(SIGHUP, signal_free);  /* NOTE: SIGHUP is sent while detaching proccess from
                                       controling terminal */
      signal(SIGTERM, signal_exit);

      tree_free(&root);
      fprintf(stdout, "Listening on %s...\n", device_name);
      while(1)
        if((packet = (char *)pcap_next(handle, &header)) != NULL && phandler(packet))
          break;
    }
    else
      fprintf(stdout, "Unknown link type code: %d\n", link_type);

    pcap_close(handle);

    return 0;
  }
  else
  {
    fprintf(stdout, "Libpcap error: %s\n", error_buff);
    return 1;
  }
}
