/* N F Q 6 */

/* System headers */

#define _GNU_SOURCE                /* To get memmem */
#include <poll.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <netinet/ip6.h>
#include <sys/resource.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>

/* NFQA_CT requires CTA_* attributes defined in nfnetlink_conntrack.h */
#include <linux/netfilter/nfnetlink_conntrack.h>

/* Macros */

#define NUM_TESTS 24
#define NUM_NLIF_BITS 4
#define NUM_NLIF_ENTRIES (1 << NUM_NLIF_BITS)
#define NLIF_ENTRY_MASK (NUM_NLIF_ENTRIES -1)

/* If bool is a macro, get rid of it */
#ifdef bool
#undef bool
#undef true
#undef false
#endif

/* Typedefs */

/* Enable gdb to show Booleans as "true" or "false" */
typedef enum bool
{
  false,
  true
} bool;

/* Structures */

struct ifindex_node
{
  struct list_head head;           /* i.e. list in this bucket */
  uint32_t index;
  uint32_t type;
  uint32_t flags;
  char name[IFNAMSIZ];
};                                 /* struct ifindex_node; */
struct nlif_handle
{
  struct list_head ifindex_hash[NUM_NLIF_ENTRIES];
};                                 /* static struct nlif_handle */

/* Static Variables */

static struct mnl_socket *nl;
/* Largest possible packet payload, plus netlink data overhead: */
static char nlrxbuf[0xffff + 4096];
static char nltxbuf[sizeof nlrxbuf];
static struct pkt_buff *pktb;
static bool tests[NUM_TESTS] = { false };
static bool sent_q;
static uint32_t packet_mark;
static int alternate_queue;
static bool quit;
static socklen_t wanted_size = 1024 * 1024 * 8;
static socklen_t socklen = sizeof wanted_size;
static socklen_t read_size;
static struct sockaddr_nl snl = {.nl_family = AF_NETLINK };
static char *myP;
static uint8_t myPROTO, myPreviousPROTO = IPPROTO_IP;
static uint32_t queuelen;
static struct nlif_handle ih;
static int qfd = -1;
static int ifd = -1;

/* Static prototypes */

static struct ifindex_node *find_ifindex_node(uint32_t index);
static int data_cb(const struct nlmsghdr *nlh, void *data);
static uint8_t ip6_get_proto(const struct nlmsghdr *nlh, struct ip6_hdr *ip6h);
static void usage(void);
static int queue_cb(const struct nlmsghdr *nlh, void *data);
static void send_verdict(int queue_num, uint32_t id, bool accept);

/* Generic function pointers */

static int (*my_xxp_mangle_ipvy)(struct pkt_buff *, unsigned int, unsigned int,
  const char *, unsigned int);
static void *(*my_xxp_get_hdr)(struct pkt_buff *);
static void *(*my_xxp_get_payload)(void *, struct pkt_buff *);
static unsigned int (*my_xxp_get_payload_len)(void *, struct pkt_buff *);
static void *(*my_ipy_get_hdr)(struct pkt_buff *);

/* ********************************** main ********************************** */

int
main(int argc, char *argv[])
{
  struct nlmsghdr *nlh;
  int ret;
  unsigned int portid, queue_num, iportid;
  int i;
  size_t sperrume;                 /* Spare room */
  uint32_t config_flags;
  uint32_t seq;
  struct mnl_socket *inl;
  struct rtgenmsg *rt;
  struct pollfd fds[2];

  while ((i = getopt(argc, argv, "a:hq:t:")) != -1)
  {
    switch (i)
    {
      case 'a':
        alternate_queue = atoi(optarg);
        if (alternate_queue <= 0 || alternate_queue > 0xffff)
        {
          fprintf(stderr, "Alternate queue number %d is out of range\n",
            alternate_queue);
          exit(EXIT_FAILURE);
        }            /* if (alternate_queue <= 0 || alternate_queue > 0xffff) */
        break;

      case 'h':
        usage();
        return 0;

      case 'q':
        queuelen = (uint32_t)atoi(optarg);
        break;

      case 't':
        ret = atoi(optarg);
        if (ret < 0 || ret >= NUM_TESTS)
        {
          fprintf(stderr, "Test %d is out of range\n", ret);
          exit(EXIT_FAILURE);
        }                          /* if (ret < 0 || ret > NUM_TESTS) */
        tests[ret] = true;
        break;

      case '?':
        exit(EXIT_FAILURE);
    }                              /* switch (i) */
  }                                /* while () */

  if (argc == optind)
  {
    fputs("Missing queue number\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (argc == optind) */
  queue_num = atoi(argv[optind]);

  if (tests[5])
    tests[4] = true;

  if (tests[4] && !alternate_queue)
  {
    fputs("Missing alternate queue number for test 4\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[4] && !alternate_queue) */

  setlinebuf(stdout);

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }                                /* if (nl == NULL) */

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }                    /* if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) */
  portid = mnl_socket_get_portid(nl);
  qfd = mnl_socket_get_fd(nl);

  if (tests[13])
  {
    if (setsockopt(qfd, SOL_SOCKET, SO_RCVBUFFORCE,
      &wanted_size, sizeof(socklen_t)) == -1)
      fprintf(stderr, "%s. setsockopt SO_RCVBUFFORCE 0x%x\n", strerror(errno),
        wanted_size);
  }                                /* if (tests[13]) */
  getsockopt(qfd, SOL_SOCKET, SO_RCVBUF, &read_size, &socklen);
  printf("Read buffer set to 0x%x bytes (%.3gMB)\n", read_size,
    read_size / (1024.0 * 1024));

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_UNSPEC, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }                    /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  config_flags = htonl((tests[20] ? 0 : NFQA_CFG_F_GSO) |
    (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0));
  if (config_flags)
  {
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, config_flags);
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, config_flags);
  }                                /* if (config_flags) */

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }                    /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */

  if (tests[23])
  {
    nlh = nfq_nlmsg_put2(nltxbuf, NFQNL_MSG_CONFIG, queue_num, NLM_F_ACK);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_SECCTX));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_SECCTX));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_send");
      exit(EXIT_FAILURE);
    }                  /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */

    ret = mnl_socket_recvfrom(nl, nlrxbuf, sizeof nlrxbuf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      exit(EXIT_FAILURE);
    }                              /* if (ret == -1) */

    ret = mnl_cb_run(nlrxbuf, ret, 0, portid, NULL, NULL);
    if (ret == -1)
      perror("configure NFQA_CFG_F_SECCTX");
  }                                /* if (tests[23]) */

  if (tests[22])
  {
    nlh = nfq_nlmsg_put2(nltxbuf, NFQNL_MSG_CONFIG, queue_num, NLM_F_ACK);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_CONNTRACK));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_send");
      exit(EXIT_FAILURE);
    }                  /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */

    ret = mnl_socket_recvfrom(nl, nlrxbuf, sizeof nlrxbuf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      exit(EXIT_FAILURE);
    }                              /* if (ret == -1) */

    ret = mnl_cb_run(nlrxbuf, ret, 0, portid, NULL, NULL);
    if (ret == -1)
      perror("configure NFQA_CFG_F_CONNTRACK");
  }                                /* if (tests[22]) */

  if (queuelen)
  {
    nlh = nfq_nlmsg_put2(nltxbuf, NFQNL_MSG_CONFIG, queue_num, NLM_F_ACK);
    mnl_attr_put_u32(nlh, NFQA_CFG_QUEUE_MAXLEN, htonl(queuelen));
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_send");
      exit(EXIT_FAILURE);
    }                  /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */
    ret = mnl_socket_recvfrom(nl, nlrxbuf, sizeof nlrxbuf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      exit(EXIT_FAILURE);
    }                              /* if (ret == -1) */
    ret = mnl_cb_run(nlrxbuf, ret, 0, portid, NULL, NULL);
    if (ret == -1)
      fprintf(stderr, "Set queue size %u: %s\n", queuelen, strerror(errno));
  }                                /* if (queuelen) */

/* ENOBUFS is signalled to userspace when packets were lost
 * on kernel side.  In most cases, userspace isn't interested
 * in this information, so turn it off.
 */
  if (!tests[2])
  {
    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));
  }                                /* if (!tests[2]) */

/* Init rtnetlink sructures */

  //memset(&ih, 0, sizeof ih);     /* Static, will be zeroes */
  for (i = 0; i < NUM_NLIF_ENTRIES; i++)
    INIT_LIST_HEAD(&ih.ifindex_hash[i]);

/* Init rtnetlink */

  inl = mnl_socket_open(NETLINK_ROUTE);
  if (!inl)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }                                /* if (!inl) */
  ifd = mnl_socket_get_fd(inl);

  if (mnl_socket_bind(inl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }                   /* if (mnl_socket_bind(inl, 0, MNL_SOCKET_AUTOPID) < 0) */
  iportid = mnl_socket_get_portid(inl);

  nlh = mnl_nlmsg_put_header(nltxbuf);
  nlh->nlmsg_type = RTM_GETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nlh->nlmsg_seq = seq = time(NULL);
  rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
  rt->rtgen_family = AF_PACKET;
  if (mnl_socket_sendto(inl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_sendto");
    exit(EXIT_FAILURE);
  }                   /* if (mnl_socket_sendto(inl, nlh, nlh->nlmsg_len) < 0) */
  ret = mnl_socket_recvfrom(inl, nlrxbuf, sizeof(nlrxbuf));
  while (ret > 0)
  {
    ret = mnl_cb_run(nlrxbuf, ret, seq, iportid, data_cb, NULL);
    if (ret <= MNL_CB_STOP)
      break;
    ret = mnl_socket_recvfrom(inl, nlrxbuf, sizeof(nlrxbuf));
  }                                /* while (ret > 0) */
  if (ret == -1)                   /* Need to look for EINTR(?) */
  {
    perror("nlif_query");
    exit(EXIT_FAILURE);
  }                                /* if (ret == -1) */

/* Set up for poll() */
  fds[0].fd = ifd;
  fds[0].events = POLLIN;
  fds[1].fd = qfd;
  fds[1].events = POLLIN;

  for (;;)
  {
    do
      ret = poll((struct pollfd *)&fds, 2, -1);
    while (ret == -1 && errno == EINTR);
    if (ret == -1)
    {
      perror("poll");
      exit(EXIT_FAILURE);
    }                              /* if (ret == -1) */

    if (fds[0].revents & POLLIN)
    {
      ret = mnl_socket_recvfrom(inl, nlrxbuf, sizeof nlrxbuf);
      if (ret == -1)
      {
        perror("mnl_socket_recvfrom");
        exit(EXIT_FAILURE);
      }                            /* if (ret == -1) */
      ret = mnl_cb_run(nlrxbuf, ret, 0, iportid, data_cb, NULL);
      if (ret == -1)
      {
        perror("mnl_cb_run (data)");
        exit(EXIT_FAILURE);
      }                            /* if (ret == -1) */
    }                              /* if (fds[0].revents & POLLIN) */

    if (fds[1].revents & POLLIN)
    {
      ret = mnl_socket_recvfrom(nl, nlrxbuf, sizeof nlrxbuf);
      if (ret == -1)
      {
        perror("mnl_socket_recvfrom");
        if (errno == ENOBUFS)
          continue;
        exit(EXIT_FAILURE);
      }                            /* if (ret == -1) */
      assert(((struct nlmsghdr *)nlrxbuf)->nlmsg_len == ret);
      sperrume = sizeof nlrxbuf - ret;

      ret = mnl_cb_run(nlrxbuf, ret, 0, portid, queue_cb, &sperrume);
      if (ret < 0 && (errno != EINTR || tests[14]))
      {
        perror("mnl_cb_run");
        if (errno != EINTR)
          exit(EXIT_FAILURE);
      }                      /* if (ret < 0 && (errno != EINTR || tests[14])) */
      if (quit)
        break;
    }                              /* if (fds[1].revents & POLLIN) */
  }                                /* for (;;) */

  mnl_socket_close(nl);
  mnl_socket_close(inl);

  return 0;
}                                  /* main() */

/* ****************************** send_verdict ****************************** */

static void
send_verdict(int queue_num, uint32_t id, bool accept)
{
  struct nlmsghdr *nlh;
  struct nlattr *nest;
  bool done = false;

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_VERDICT, queue_num);

  if (!accept)
  {
    nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
    goto send_verdict;
  }                                /* if (!accept) */

  if (tests[21])
  {
    nest = mnl_attr_nest_start(nlh, NFQA_CT);
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
    mnl_attr_nest_end(nlh, nest);
  }                                /* if (tests[21]) */

  if (tests[0] && !packet_mark)
  {
    nfq_nlmsg_verdict_put_mark(nlh, 0xbeef);
    nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    done = true;
  }                                /* if (tests[0] && !packet_mark) */

  if (tests[1] && !done)
  {
    if (packet_mark == 0xfaceb00c)
      nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
    else
    {
      nfq_nlmsg_verdict_put_mark(nlh, 0xfaceb00c);
      nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    }                              /* if (packet_mark == 0xfaceb00c) else */
    done = true;
  }                                /* if (tests[1] && !done) */

  if (tests[4] && !done)
  {
    nfq_nlmsg_verdict_put(nlh, id,
      NF_QUEUE_NR(alternate_queue) | (tests[5] ? NF_VERDICT_FLAG_QUEUE_BYPASS :
      0));
    done = true;
  }                                /* if (tests[4] && !done) */

  if (!done)
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

  if (pktb_mangled(pktb) && tests[8])
  {
    struct nlattr *attrib = mnl_nlmsg_get_payload_tail(nlh);
    size_t len = pktb_len(pktb);
    struct iovec iov[2];
    const struct msghdr msg = {
      .msg_name = &snl,
      .msg_namelen = sizeof snl,
      .msg_iov = iov,
      .msg_iovlen = 2,
      .msg_control = NULL,
      .msg_controllen = 0,
      .msg_flags = 0,
    };                             /* const struct msghdr msg = */

    attrib->nla_type = NFQA_PAYLOAD;
    attrib->nla_len = sizeof(struct nlattr) + len;
    nlh->nlmsg_len += sizeof(struct nlattr);
    iov[0].iov_base = nlh;
    iov[0].iov_len = nlh->nlmsg_len;
    iov[1].iov_base = pktb_data(pktb);
    iov[1].iov_len = len;
    nlh->nlmsg_len += len;
    if (sendmsg(qfd, &msg, 0) < 0)
    {
      perror("sendmsg");
      exit(EXIT_FAILURE);
    }                              /* if (sendmsg(qfd, &msg, 0) < 0) */
  }                                /* if (pktb_mangled(pktb) && tests[8]) */
  else
  {
    if (pktb_mangled(pktb))
      nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
  send_verdict:
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_sendto");
      exit(EXIT_FAILURE);
    }                  /* if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) */
  }                                /* if (pktb_mangled(pktb) && tests[8] else */
}                                  /* send_verdict() */

/* ******************************** queue_cb ******************************** */

#ifdef GIVE_UP
#undef GIVE_UP
#endif
#define GIVE_UP(x)\
do {fputs(x, stderr); goto send_verdict;} while (0)

#ifdef GIVE_UP2
#undef GIVE_UP2
#endif
#define GIVE_UP2(x, y)\
do {fprintf(stderr, x, y); goto send_verdict;} while (0)

static int
queue_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nfqnl_msg_packet_hdr *ph = NULL;
  uint32_t id = 0, skbinfo;
  struct nfgenmsg *nfg;
  uint8_t *payload;
  uint8_t *xxp_payload;
  unsigned int xxp_payload_len;
  bool accept = true;
  static struct udphdr *udph;
  static struct tcphdr *tcph;
  static struct ip6_hdr *ip6h;
  static struct iphdr *ip4h;
  static void **iphp;
  static void **xxph;
  char erbuf[4096];
  bool normal = !tests[16];        /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  uint16_t plen;
  uint8_t *p;
  struct nlattr *attr[NFQA_MAX + 1] = { };
  char *errfunc;
  char pb[pktb_head_size()];
  uint16_t nbo_proto;
  bool is_IPv4;
  static bool was_IPv4;
  struct ifindex_node *this = NULL;

  if (nfq_nlmsg_parse(nlh, attr) < 0)
  {
    perror("problems parsing");
    return MNL_CB_ERROR;
  }                                /* if (nfq_nlmsg_parse(nlh, attr) < 0) */

/* Most of the lines in this next block are individually annotated in
 * examples/nf-queue.c in the libnetfilter_queue source tree.
 */
  nfg = mnl_nlmsg_get_payload(nlh);
  if (attr[NFQA_PACKET_HDR] == NULL)
  {
    fputs("metaheader not set\n", stderr);
    return MNL_CB_ERROR;
  }                                /* if (attr[NFQA_PACKET_HDR] == NULL) */
  ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
  plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
  payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
  packet_mark = attr[NFQA_MARK] ? ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) : 0;
  skbinfo =
    attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

  if (attr[NFQA_CAP_LEN])
  {
    uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));

    if (orig_len != plen)
    {
      nc += snprintf(record_buf, sizeof record_buf, "%s", "truncated ");
      normal = false;
    }                              /* if (orig_len != plen) */
  }                                /* if (attr[NFQA_CAP_LEN]) */

  if (skbinfo & NFQA_SKB_GSO)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc, "%s", "GSO ");
    normal = false;
  }                                /* if (skbinfo & NFQA_SKB_GSO) */

  id = ntohl(ph->packet_id);
  nc += snprintf(record_buf + nc, sizeof record_buf - nc,
    "packet received (id=%u hw=0x%04x hook=%u, payload len %u", id,
    nbo_proto = ntohs(ph->hw_protocol), ph->hook, plen);

/*
 * The code from here down to "ip/tcp checksum is not yet valid"
 * determines whether this packet is IP verion 4 or 6,
 * and within that whether TCP or UDP.
 *
 * In order to avoid repeated tests on protocol and IP version,
 * the code sets up function and data pointers for generic use.
 * Most packet buffer functions have a similar enough signature between
 * protocols that they can be cast to a common prototype,
 * albeit at the cost of type checking since the common prototype
 * will contain or return void pointers.
 *
 * If you are using this program as a template for a single-protocol
 * filter, you don't need this but you do need to do the following:
 * - (suggestion only) Keep a copy of this file
 * - Delete this code chunk, as above
 * - Delete function body and declaration of ip6_get_proto
 * - Delete declarations of myP, myPROTO, myPreviousPROTO, iphp, xxph,
 *                          nbo_proto, is_IPv4 & was_IPv4
 * - Delete declaration of either ip4h or ip6h, change "*iphp" to the
 *   one you kept e.g. s/\*iphp/ip4h/g
 * - Similarly, delete declaration of either tcph or udph, and change
 *   "*xxph" to the one you kept.
 * - Delete the generic function pointer declarations
 * - Edit generic function names (and other code) back to specifics:
 *   - "my_"  becomes "nfq_"
 *   - "xxp"  becomes "tcp"  or "udp"
 *   - "ipvy" becomes "ipv4" or "ipv6"
 *   - "ipy"  becomes "ip"   or "ip6" (1 occurrence)
 *   E.g. for udp4, my_xxp_mangle_ipvy becomes nfq_udp_mangle_ipv4.
 * - Replace myPROTO with IPPROTO_TCP or IPPROTO_UDP
 * - You *can* replace "is_IPv4" by "true" or "false" and similarly
 *   replace "myP" with "\"TCP\"" or \""UDP\"". Instead, you can edit
 *   the individual lines where these are used for a neater end result
 *
 * The rest is non-generic. From this point on, it's suggested to do
 * test compiles to see (from reported errors) where changes are still
 * required:
 * - Remove assignment of nbo_proto
 * - Fix up call to nfq_ip_set_transport_header() or
 *   nfq_ip6_set_transport_header(),
 *   to leave 2 lines from 7 lines starting "if (true) {"
 *
 * You should now have a filter program which does all that nfq6 did,
 * but only for your chosen protocol. Next you can modify it to do the
 * actual job you had in mind.
 */
  is_IPv4 = nbo_proto == ETH_P_IP;
  if (is_IPv4)
  {
    my_ipy_get_hdr = (void *)nfq_ip_get_hdr;
    iphp = (void **)&ip4h;
    myPROTO = ((struct iphdr *)payload)->protocol;
  }                                /* if (is_IPv4) */
  else
  {
    if (nbo_proto != ETH_P_IPV6)
      GIVE_UP2("Unrecognised L3 protocol: 0x%04hx\n", nbo_proto);
    my_ipy_get_hdr = (void *)nfq_ip6_get_hdr;
    iphp = (void **)&ip6h;
    myPROTO = ip6_get_proto(nlh, (struct ip6_hdr *)payload);
  }                                /* if (is_IPv4) else */

/* Speedup: skip setting pointers if L3 & L4 protos same as last time */
/* (usual case) */
  if (!(is_IPv4 == was_IPv4 && myPROTO == myPreviousPROTO))
  {
    was_IPv4 = is_IPv4;
    myPreviousPROTO = myPROTO;
    if (myPROTO == IPPROTO_TCP)
    {
      xxph = (void **)&tcph;
      my_xxp_mangle_ipvy = is_IPv4 ? nfq_tcp_mangle_ipv4 : nfq_tcp_mangle_ipv6;
      myP = "TCP";
      my_xxp_get_hdr = (void *)nfq_tcp_get_hdr;
      my_xxp_get_payload =
        (void *(*)(void *, struct pkt_buff *))nfq_tcp_get_payload;
      my_xxp_get_payload_len =
        (unsigned int (*)(void *, struct pkt_buff *))nfq_tcp_get_payload_len;
    }                              /* if (myPROTO == IPPROTO_TCP) */
    else if (myPROTO == IPPROTO_UDP)
    {
      xxph = (void **)&udph;
      my_xxp_mangle_ipvy = is_IPv4 ? nfq_udp_mangle_ipv4 : nfq_udp_mangle_ipv6;
      myP = "UDP";
      my_xxp_get_hdr = (void *)nfq_udp_get_hdr;
      my_xxp_get_payload =
        (void *(*)(void *, struct pkt_buff *))nfq_udp_get_payload;
      my_xxp_get_payload_len =
        (unsigned int (*)(void *, struct pkt_buff *))nfq_udp_get_payload_len;
    }                              /* else if (myPROTO == IPPROTO_UDP) */
    else
      GIVE_UP2("Unrecognised L4 protocol: %02hhu\n", myPROTO);
  }                                /* if (!(is_IPv4 == was_IPv4 && ... */

/*
 * ip/tcp checksum is not yet valid, e.g. due to GRO/GSO or IPv6.
 * The application should behave as if the checksum is correct.
 *
 * If this packet is later forwarded/sent out, the checksum will
 * be corrected by kernel/hardware.
 *
 * If we mangle this packet,
 * the called function will update the checksum.
 */
  if (skbinfo & NFQA_SKB_CSUMNOTREADY)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", checksum not ready");
    if (ntohs(ph->hw_protocol) != ETH_P_IPV6 || tests[15])
      normal = false;
  }                                /* if (skbinfo & NFQA_SKB_CSUMNOTREADY) */

  if (attr[NFQA_IFINDEX_INDEV])
  {
    uint32_t indev = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_INDEV]));

    this = find_ifindex_node(indev);
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", indev = %u(%s)", indev, this ? this->name : "");
  }                                /* if (attr[NFQA_IFINDEX_INDEV]) */

  if (attr[NFQA_IFINDEX_OUTDEV])
  {
    uint32_t outdev = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_OUTDEV]));

    this = find_ifindex_node(outdev);
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", outdev = %u(%s)", outdev, this ? this->name : "");
  }                                /* if (attr[NFQA_IFINDEX_OUTDEV]) */

  if (!normal)
    printf("%s)\n", record_buf);

/* Set up a packet buffer. If copying data, allow 255 bytes extra room;
 * otherwise use extra room in the receive buffer.
 * AF_INET6 and AF_INET work the same, no need to look at is_IPv4
 */
#define EXTRA 255
  if (tests[7])
  {
    pktb = pktb_setup_raw(pb, AF_INET6, payload, plen, *(size_t *)data);
    errfunc = "pktb_setup_raw";
  }                                /* if (tests[7]) */
  else
  {
    pktb = pktb_alloc(AF_INET6, payload, plen, EXTRA);
    errfunc = "pktb_alloc";
  }                                /* if (!tests[7] else */
  if (!pktb)
  {
    snprintf(erbuf, sizeof erbuf, "%s. (%s)\n", strerror(errno), errfunc);
    GIVE_UP(erbuf);
  }                                /* if (!pktb) */

  if (!(*iphp = my_ipy_get_hdr(pktb)))
    GIVE_UP2("Malformed IPv%c\n", is_IPv4 ? '4' : '6');

  if (is_IPv4)
  {
    if (nfq_ip_set_transport_header(pktb, *iphp))
      GIVE_UP("No payload found\n");
  }                                /* if (is_IPv4) */
  else
  {
    if (!nfq_ip6_set_transport_header(pktb, *iphp, myPROTO))
      GIVE_UP2("No %s payload found\n", myP);
  }                                /* if (is_IPv4) else */
  if (!(*xxph = my_xxp_get_hdr(pktb)))
    GIVE_UP2("Packet too short to get %s header\n", myP);
  if (!(xxp_payload = my_xxp_get_payload(*xxph, pktb)))
    GIVE_UP2("Packet too short to get %s payload\n", myP);
  xxp_payload_len = my_xxp_get_payload_len(*xxph, pktb);

  if (tests[6] && xxp_payload_len >= 2 && xxp_payload[0] == 'q' &&
    isspace(xxp_payload[1]))
  {
    if (tests[4] && !sent_q)
      sent_q = true;
    else
    {
      accept = false;              /* Drop this packet */
      quit = true;                 /* Exit after giving verdict */
    }                              /* if (tests[4] && !sent_q else */
  }                              /* if (tests[6] && strchr(xxp_payload, 'q')) */

  if (tests[9] && (p = memmem(xxp_payload, xxp_payload_len, "ASD", 3)))
  {
    my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "F", 1);
    xxp_payload_len -= 2;
  }                                /* tests[9] */

  if (tests[10] && (myPROTO == IPPROTO_UDP || tests[19]) &&
    (p = memmem(xxp_payload, xxp_payload_len, "QWE", 3)))
  {
    if (my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "RTYUIOP", 7))
      xxp_payload_len += 4;
    else
      fputs("QWE -> RTYUIOP mangle FAILED\n", stderr);
  }                     /* if (tests[10] && (p = strstr(xxp_payload, "QWE"))) */

  if (tests[11] && (p = memmem(xxp_payload, xxp_payload_len, "ASD", 3)))
  {
    my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "G", 1);
    xxp_payload_len -= 2;
  } /* if (tests[11] && (p = memmem(xxp_payload, xxp_payload_len, "ASD", 3))) */

  if (tests[12] && (myPROTO == IPPROTO_UDP || tests[19]) &&
    (p = memmem(xxp_payload, xxp_payload_len, "QWE", 3)))
  {
    if (my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "MNBVCXZ", 7))
      xxp_payload_len += 4;
    else
      fputs("QWE -> MNBVCXZ mangle FAILED\n", stderr);
  }                     /* if (tests[12] && (p = strstr(xxp_payload, "QWE"))) */

  if (tests[17] && (p = memmem(xxp_payload, xxp_payload_len, "ZXC", 3)))
    my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "VBN", 3);

  if (tests[18] && (p = memmem(xxp_payload, xxp_payload_len, "ZXC", 3)))
    my_xxp_mangle_ipvy(pktb, p - xxp_payload, 3, "VBN", 3);

send_verdict:
  send_verdict(ntohs(nfg->res_id), id, accept);

  if (!tests[7])
    pktb_free(pktb);

  return MNL_CB_OK;
}                                  /* queue_cb() */

/* ********************************** usage ********************************* */

static void
usage(void)
{
/* N.B. Trailing empty comments are there to stop gnu indent joining lines */
  puts("\nUsage: nfq6 [-a <alt q #>] " /*  */
    "[-q <queue length>] "         /*  */
    "[-t <test #>]... queue_number\n" /*  */
    "       nfq6 -h\n"             /*  */
    "  -a <n>: Alternate queue for test 4\n" /*  */
    "  -h: give this Help and exit\n" /*  */
    "  -q <n>: Set queue length to <n>\n" /*  */
    "  -t <n>: do Test <n>. Tests are:\n" /*  */
    "    0: If packet mark is zero, set it to 0xbeef and give verdict " /*  */
    "NF_REPEAT\n"                  /*  */
    "    1: If packet mark is not 0xfaceb00c, set it to 0xfaceb00c\n" /*  */
    "       and give verdict NF_REPEAT\n" /*  */
    "       If packet mark *is* 0xfaceb00c, accept the packet\n" /*  */
    "    2: Allow ENOBUFS to happen; treat as harmless when it does\n" /*  */
    "    3: Configure NFQA_CFG_F_FAIL_OPEN\n" /*  */
    "    4: Send packets to alternate -a queue\n" /*  */
    "    5: Force on test 4 and specify BYPASS\n" /*  */
    "    6: Exit nfq6 if incoming packet starts \"q[[:space:]]\"" /*  */
    " (e.g. q\\n)\n"               /*  */
    "    7: Use pktb_setup_raw\n"  /*  */
    "    8: Use sendmsg to avoid memcpy after mangling\n" /*  */
    "    9: Replace 1st ASD by F\n" /*  */
    "   10: Replace 1st QWE by RTYUIOP (UDP packets only)\n" /*  */
    "   11: Replace 2nd ASD by G\n" /*  */
    "   12: Replace 2nd QWE by MNBVCXZ (UDP packets only)\n" /*  */
    "   13: Set 16MB kernel socket buffer\n" /*  */
    "   14: Report EINTR if we get it\n" /*  */
    "   15: Log netlink packets with no checksum\n" /*  */
    "   16: Log all netlink packets\n" /*  */
    "   17: Replace 1st ZXC by VBN\n" /*  */
    "   18: Replace 2nd ZXC by VBN\n" /*  */
    "   19: Enable tests 10 & 12 for TCP (not recommended)\n" /*  */
    "   20: Don't configure NFQA_CFG_F_GSO\n" /*  */
    "   21: Send a nested connmark\n" /*  */
    "   22: Turn on NFQA_CFG_F_CONNTRACK\n" /*  */
    "   23: Turn on NFQA_CFG_F_SECCTX\n" /*  */
    );
}                                  /* static void usage(void) */

/* ****************************** ip6_get_proto ***************************** */

static uint8_t
ip6_get_proto(const struct nlmsghdr *nlh, struct ip6_hdr *ip6h)
{
/* This code is a copy of nfq_ip6_set_transport_header(), modified to return the
 * upper-layer protocol instead. */

  uint8_t nexthdr = ip6h->ip6_nxt;
  uint8_t *cur = (uint8_t *)ip6h + sizeof(struct ip6_hdr);
  const uint8_t *pkt_tail = (const uint8_t *)nlh + nlh->nlmsg_len;

/* Speedup: save 4 compares in the usual case (no extension headers) */
  if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)
    return nexthdr;                /* Ugly but it saves an indent level */

  while (nexthdr == IPPROTO_HOPOPTS ||
    nexthdr == IPPROTO_ROUTING ||
    nexthdr == IPPROTO_FRAGMENT ||
    nexthdr == IPPROTO_AH ||
    nexthdr == IPPROTO_NONE || nexthdr == IPPROTO_DSTOPTS)
  {
    struct ip6_ext *ip6_ext;
    uint32_t hdrlen;

/* No more extensions, we're done. */
    if (nexthdr == IPPROTO_NONE)
      break;
/* No room for extension, bad packet. */
    if (pkt_tail - cur < sizeof(struct ip6_ext))
    {
      nexthdr = IPPROTO_NONE;
      break;
    }                         /* if (pkt_tail - cur < sizeof(struct ip6_ext)) */
    ip6_ext = (struct ip6_ext *)cur;

    if (nexthdr == IPPROTO_FRAGMENT)
    {

/* No room for full fragment header, bad packet. */
      if (pkt_tail - cur < sizeof(struct ip6_frag))
      {
        nexthdr = IPPROTO_NONE;
        break;
      }                      /* if (pkt_tail - cur < sizeof(struct ip6_frag)) */

/* Fragment offset is only 13 bits long. */
      if (ntohs(((struct ip6_frag *)cur)->ip6f_offlg) & ~0x7)
      {

/* Not the first fragment, it does not contain any headers. */
        nexthdr = IPPROTO_NONE;
        break;
      }            /* if (ntohs(((struct ip6_frag *)cur)->ip6f_offlg) & ~0x7) */
      hdrlen = sizeof(struct ip6_frag);
    }                              /* if (nexthdr == IPPROTO_FRAGMENT) */
    else if (nexthdr == IPPROTO_AH)
      hdrlen = (ip6_ext->ip6e_len + 2) << 2;
    else
      hdrlen = (ip6_ext->ip6e_len + 1) << 3;

    nexthdr = ip6_ext->ip6e_nxt;
    cur += hdrlen;
  }
  return nexthdr;
}                                  /* ip6_get_proto() */

/* ********************************* data_cb ******************************** */

static int
data_cb(const struct nlmsghdr *nlh, void *data)
{
  struct ifinfomsg *ifi_msg = mnl_nlmsg_get_payload(nlh);
  struct nlattr *attr;
  struct ifindex_node *this, *tmp;
  uint32_t hash = ifi_msg->ifi_index & NLIF_ENTRY_MASK;;

  if (nlh->nlmsg_type != RTM_NEWLINK && nlh->nlmsg_type != RTM_DELLINK)
  {
    errno = EPROTO;
    return MNL_CB_ERROR;
  }                              /* if (nlh->nlmsg_type != RTM_NEWLINK && ... */

/* RTM_DELLINK is simple, do it first for less indenting */
  if (nlh->nlmsg_type == RTM_DELLINK)
  {
    list_for_each_entry_safe(this, tmp, &ih.ifindex_hash[hash], head)
    {
      if (this->index == ifi_msg->ifi_index)
      {
        list_del(&this->head);
        free(this);
      }                            /* if (this->index == ifi_msg->ifi_index) */
    }   /* list_for_each_entry_safe(this, tmp, &ih->ifindex_hash[hash], head) */
    return MNL_CB_OK;
  }                                /* if (nlh->nlmsg_type == RTM_DELLINK) */

  this = find_ifindex_node(ifi_msg->ifi_index);
  if (!this)
  {
    this = malloc(sizeof(*this));
    if (!this)
      return MNL_CB_ERROR;
    this->index = ifi_msg->ifi_index;
    this->type = ifi_msg->ifi_type;
    this->flags = ifi_msg->ifi_flags;
    this->name[0] = 0;
    list_add(&this->head, &ih.ifindex_hash[hash]);
  }                                /* if (!this) */

  mnl_attr_for_each(attr, nlh, sizeof(*ifi_msg))
  {
/* All we want is the interface name */
    if (mnl_attr_get_type(attr) == IFLA_IFNAME)
    {
      if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
      {
        perror("mnl_attr_validate");
        return MNL_CB_ERROR;
      }                  /* if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) */
      strcpy(this->name, mnl_attr_get_str(attr));
      break;
    }                           /* if(mnl_attr_get_type(attr) == IFLA_IFNAME) */
  }                         /* mnl_attr_for_each(attr, nlh, sizeof(*ifi_msg)) */
  return MNL_CB_OK;
}                                  /* data_cb() */

/* **************************** find_ifindex_node *************************** */

static struct ifindex_node *
find_ifindex_node(uint32_t index)
{
  struct ifindex_node *result;
  uint32_t hash;

  if (index == 0)
  {
    errno = ENOENT;
    return NULL;
  }                                /* if (index == 0) */

  hash = index & NLIF_ENTRY_MASK;
  list_for_each_entry(result, &ih.ifindex_hash[hash], head)
  {
    if (result->index == index)
      return result;
  }              /* list_for_each_entry(result, &ih.ifindex_hash[hash], head) */
  errno = ENOENT;
  return NULL;
}                                  /* find_ifindex_node() */
