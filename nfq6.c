/* N F Q 6 */

/* pragmas */

#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wpointer-arith"

/* config.h */

#include "config.h"

/* System headers */

#define _GNU_SOURCE
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/ip.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <sys/resource.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/pktbuff.h>
#ifdef HAVE_PKTB_SETUP
#include <libnetfilter_queue/callback.h>
#endif
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>

/* Macros */

#define NUM_TESTS 22

/* If bool is a macro, get rid of it */

#ifdef bool
#undef bool
#undef true
#undef false
#endif

/* Headers */

#include "prototypes.h"
#include "typedefs.h"

/* Static Variables */

static struct mnl_socket *nl;
/* Largest possible packet payload, plus netlink data overhead: */
static char nlrxbuf[0xffff + 4096];
static char nltxbuf[sizeof nlrxbuf];
static struct pkt_buff *pktb;
static bool tests[NUM_TESTS] = { false };
static uint32_t packet_mark;
static int alternate_queue = 0;
static bool quit = false;
static socklen_t buffersize = 1024 * 1024 * 8;
static socklen_t socklen = sizeof buffersize, read_size = 0;
static struct sockaddr_nl snl = {.nl_family = AF_NETLINK };

/* Static prototypes */

#ifdef HAVE_PKTB_SETUP
static int queue_cb_new(const struct nlmsghdr *nlh, void *data,
  size_t supplied_extra);
#endif
static int queue_cb_common(const struct nlmsghdr *nlh, void *data,
  struct pkt_buff *supplied_pktb, size_t supplied_extra);
static void usage(void);
static int queue_cb(const struct nlmsghdr *nlh, void *data);
static void nfq_send_verdict(int queue_num, uint32_t id, bool accept);

/* ********************************** main ********************************** */

int
main(int argc, char *argv[])
{
  struct nlmsghdr *nlh;
  int ret;
  unsigned int portid, queue_num;
  int i;
#ifdef HAVE_PKTB_SETUP
# ifndef HAVE_PKTB_HEAD_SIZE
# error "Inconsistent config: HAVE_PKTB_SETUP but not HAVE_PKTB_HEAD_SIZE"
# endif
  char pkt_b[pktb_head_size()];
#endif
#ifdef HAVE_PKTB_SETUP_RAW
size_t sperrume;                   /* Spare room (strine) */
#endif

  while ((i = getopt(argc, argv, "a:ht:")) != -1)
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
  }
  queue_num = atoi(argv[optind]);

  if (tests[5])
    tests[4] = true;

  if (tests[4] && !alternate_queue)
  {
    fputs("Missing alternate queue number for test 4\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[4] && !alternate_queue) */
  if (tests[7])
  {
    fputs("Test 7 is not available\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[7]) */
#ifndef HAVE_PKTB_SETUP
  if (tests[19])
  {
    fputs("Test 19 is not available\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[7]) */
#endif
#ifndef HAVE_PKTB_SETUP_RAW
  if (tests[21])
  {
    fputs("Test 21 is not available\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[7]) */
#endif

  if (tests[19] && tests[7])
  {
    fputs("Tests 7 & 19 are mutually exclusive\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[19] && tests[7]) */

  setlinebuf(stdout);

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }
  portid = mnl_socket_get_portid(nl);

  if (tests[20])
  {
    if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUFFORCE,
      &buffersize, sizeof(socklen_t)) == -1)
      fprintf(stderr, "%s. setsockopt SO_RCVBUFFORCE 0x%x\n", strerror(errno),
        buffersize);
  }                                /* if (tests[20]) */
  getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUF, &read_size,
    &socklen);
  printf("Read buffer set to 0x%x bytes (%dMB)\n", read_size,
    read_size / (1024 * 1024));

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS,
    htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));
  mnl_attr_put_u32(nlh, NFQA_CFG_MASK,
    htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

/* ENOBUFS is signalled to userspace when packets were lost
 * on kernel side.  In most cases, userspace isn't interested
 * in this information, so turn it off.
 */
  if (!tests[2])
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

  for (;;)
  {
    ret = mnl_socket_recvfrom(nl, nlrxbuf, sizeof nlrxbuf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      if (errno == ENOBUFS)
        continue;
      exit(EXIT_FAILURE);
    }
    assert(((struct nlmsghdr *)nlrxbuf)->nlmsg_len == ret);
#ifdef HAVE_PKTB_SETUP_RAW
    sperrume = sizeof nlrxbuf - ret;
#endif

#ifdef HAVE_PKTB_SETUP
    if (tests[19])
      ret =
        nfq_cb_run(nlrxbuf, ret, sizeof nlrxbuf, portid, queue_cb_new, pkt_b);
    else
#endif
      ret = mnl_cb_run(nlrxbuf, ret, 0, portid, queue_cb,
#ifdef HAVE_PKTB_SETUP_RAW
        &sperrume);
#else
        NULL);
#endif
    if (ret < 0 && !(errno == EINTR || tests[14]))
    {
      perror("mnl_cb_run");
      if (errno != EINTR)
        exit(EXIT_FAILURE);
    }
  }

  mnl_socket_close(nl);

  return 0;
}

/* **************************** nfq_send_verdict **************************** */

static void
nfq_send_verdict(int queue_num, uint32_t id, bool accept)
{
  struct nlmsghdr *nlh;
  bool done = false;
  int iovidx;
  struct iovec iov[4];
  int32_t padbuf;

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_VERDICT, queue_num);

  if (tests[8])
  {
    iov[0].iov_base = nlh;
    iovidx = 0;
  }                                /* if (tests[8]) */

  if (!accept)
  {
    nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
    goto send_verdict;
  }                                /* if (!accept) */

  if (pktb_mangled(pktb))
  {
    if (tests[8])
    {
      struct nlattr *attrib = mnl_nlmsg_get_payload_tail(nlh);
      size_t len = pktb_len(pktb);
      uint16_t payload_len = MNL_ALIGN(sizeof(struct nlattr)) + len;
      int pad;

      attrib->nla_type = NFQA_PAYLOAD;
      attrib->nla_len = payload_len;
      nlh->nlmsg_len += sizeof(struct nlattr);
      iov[iovidx].iov_len = nlh->nlmsg_len;
      iov[++iovidx].iov_base = pktb_data(pktb);
      iov[iovidx].iov_len = len;
      pad = MNL_ALIGN(len) - len;
      if (pad)
      {
        padbuf = 0;
        iov[++iovidx].iov_base = &padbuf;
        iov[iovidx].iov_len = pad;
      }                            /* if (pad) */
      iov[++iovidx].iov_base = iov[0].iov_base + iov[0].iov_len;
    }                              /* if (tests[8]) */
    else
      nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
  }                                /* if (pktb_mangled(pktb)) */

  if (tests[0] && !packet_mark)
  {
    nfq_nlmsg_verdict_put_mark(nlh, 0xbeef);
    nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    done = true;
  }                                /* if (tests[0] */

  if (tests[1] && !done)
  {
    if (packet_mark == 0xfaceb00c)
      nfq_nlmsg_verdict_put(nlh, id, NF_STOP);
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

send_verdict:
  if (tests[8])
  {
    const struct msghdr msg = {
      .msg_name = &snl,
      .msg_namelen = sizeof snl,
      .msg_iov = iov,
      .msg_iovlen = iovidx + (iov[iovidx].iov_len ? 1 : 0),
      .msg_control = NULL,
      .msg_controllen = 0,
      .msg_flags = 0,
    };                             /* const struct msghdr msg = */

    if (iovidx)
    {
      int i;

      iov[iovidx].iov_len = nlh->nlmsg_len - iov[0].iov_len;
      for (i = 1; i < iovidx; i++)
        nlh->nlmsg_len += iov[i].iov_len;
    }                              /* if (iovidx) */
    else
      iov[0].iov_len = nlh->nlmsg_len;

    if (sendmsg(mnl_socket_get_fd(nl), &msg, 0) < 0)
    {
      perror("sendmsg");
      exit(EXIT_FAILURE);
    }                     /* if (sendmsg(mnl_socket_get_fd(nl), &msg, 0) < 0) */
  }                                /* if (tests[8]) */
  else
  {
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_sendto");
      exit(EXIT_FAILURE);
    }
  }                                /* if (tests[8]) else */
  if (quit)
    exit(0);
}

/* ******************************** queue_cb ******************************** */

#ifdef GIVE_UP
#undef GIVE_UP
#endif
#define GIVE_UP(x)\
do {fputs(x, stderr); accept = false; goto send_verdict;} while (0)

static int
queue_cb(const struct nlmsghdr *nlh, void *data)
{
  return queue_cb_common(nlh, data, NULL, 0);
}

/* ****************************** queue_cb_new ****************************** */

#ifdef HAVE_PKTB_SETUP
static int
queue_cb_new(const struct nlmsghdr *nlh, void *data, size_t supplied_extra)
{
  return queue_cb_common(nlh, data, data, supplied_extra);
}
#endif

/* ***************************** queue_cb_common **************************** */

static int
queue_cb_common(const struct nlmsghdr *nlh, void *data,
  struct pkt_buff *supplied_pktb, size_t supplied_extra)
{
  struct nfqnl_msg_packet_hdr *ph = NULL;
  uint32_t id = 0, skbinfo;
  struct nfgenmsg *nfg;
  uint8_t *payload;
  uint8_t *xxp_payload;
  unsigned int xxp_payload_len;
  bool accept = true;
  struct udphdr *udph;
  struct tcphdr *tcph;
  struct ip6_hdr *iph;
  char erbuf[4096];
  bool normal = !tests[16];        /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  uint16_t plen;
  uint8_t *p;
  struct nlattr *attr[NFQA_MAX + 1] = { };
  int (*mangler) (struct pkt_buff *, unsigned int, unsigned int, const char *,
    unsigned int);
  char *errfunc;
#ifdef HAVE_PKTB_SETUP_RAW
  char pb[pktb_head_size()];
#endif

  if (nfq_nlmsg_parse(nlh, attr) < 0)
  {
    perror("problems parsing");
    return MNL_CB_ERROR;
  }

  nfg = mnl_nlmsg_get_payload(nlh);

  if (attr[NFQA_PACKET_HDR] == NULL)
  {
    fputs("metaheader not set\n", stderr);
    return MNL_CB_ERROR;
  }

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
  }

  if (skbinfo & NFQA_SKB_GSO)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc, "%s", "GSO ");
    normal = false;
  }                                /* if (skbinfo & NFQA_SKB_GSO) */

  id = ntohl(ph->packet_id);
  nc += snprintf(record_buf + nc, sizeof record_buf - nc,
    "packet received (id=%u hw=0x%04x hook=%u, payload len %u", id,
    ntohs(ph->hw_protocol), ph->hook, plen);

/*
 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO or IPv6.
 * The application should behave as if the checksums are correct.
 *
 * If these packets are later forwarded/sent out, the checksums will
 * be corrected by kernel/hardware.
 */
  if (skbinfo & NFQA_SKB_CSUMNOTREADY)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", checksum not ready");
    if (ntohs(ph->hw_protocol) != ETH_P_IPV6 || tests[15])
      normal = false;
  }                                /* if (skbinfo & NFQA_SKB_CSUMNOTREADY) */
  if (!normal)
  {
    snprintf(record_buf + nc, sizeof record_buf - nc, ")\n");
    printf("%s", record_buf);
  }                                /* if (!normal) */

/* Copy data to a packet buffer. Allow 255 bytes extra room */
#define EXTRA 255
#ifdef HAVE_PKTB_SETUP
  if (tests[19])
  {
    pktb = pktb_setup(supplied_pktb, AF_INET6, payload, plen, supplied_extra);
    errfunc = "pktb_setup";
  }                                /* if (tests[19]) */
#endif
#ifdef HAVE_PKTB_SETUP_RAW
  if (tests[21])
  {
    pktb = pktb_setup_raw(pb, AF_INET6, payload, plen, *(size_t *)data);
  }                                /* if (tests[21]) */
#endif
  if (!tests[21] && !tests[19])
  {
    {
      pktb = pktb_alloc(AF_INET6, payload, plen, EXTRA);
      errfunc = "pktb_alloc";
    }                              /* if (tests[7]) else */
  }                                /* if (!tests[21] && !tests[19]) */
  if (!pktb)
  {
    snprintf(erbuf, sizeof erbuf, "%s. (%s)\n", strerror(errno), errfunc);
    GIVE_UP(erbuf);
  }                                /* if (!pktb) */

  if (!(iph = nfq_ip6_get_hdr(pktb)))
    GIVE_UP("Malformed IPv6\n");

  if (tests[13])
  {
    mangler = nfq_tcp_mangle_ipv6;
    if (!nfq_ip6_set_transport_header(pktb, iph, IPPROTO_TCP))
      GIVE_UP("No TCP payload found\n");
    if (!(tcph = nfq_tcp_get_hdr(pktb)))
      GIVE_UP("Packet too short to get TCP header\n");
    if (!(xxp_payload = nfq_tcp_get_payload(tcph, pktb)))
      GIVE_UP("Packet too short to get TCP payload\n");
    xxp_payload_len = nfq_tcp_get_payload_len(tcph, pktb);
  }                                /* if (tests[13]) */
  else
  {
    mangler = nfq_udp_mangle_ipv6;
    if (!nfq_ip6_set_transport_header(pktb, iph, IPPROTO_UDP))
      GIVE_UP("No UDP payload found\n");
    if (!(udph = nfq_udp_get_hdr(pktb)))
      GIVE_UP("Packet too short to get UDP header\n");
    if (!(xxp_payload = nfq_udp_get_payload(udph, pktb)))
      GIVE_UP("Packet too short to get UDP payload\n");
    xxp_payload_len = nfq_udp_get_payload_len(udph, pktb);
  }                                /* if (tests[13]) else */

  if (tests[6] && xxp_payload_len >= 2 && xxp_payload[0] == 'q' &&
    isspace(xxp_payload[1]))
  {
    accept = false;                /* Drop this packet */
    quit = true;                   /* Exit after giving verdict */
  }                              /* if (tests[6] && strchr(xxp_payload, 'q')) */

  if (tests[9] && (p = memmem(xxp_payload, xxp_payload_len, "ASD", 3)))
  {
    mangler(pktb, p - xxp_payload, 3, "F", 1);
    xxp_payload_len -= 2;
  }                                /* tests[9] */

  if (tests[10] && (p = memmem(xxp_payload, xxp_payload_len, "QWE", 3)))
  {
    if (mangler(pktb, p - xxp_payload, 3, "RTYUIOP", 7))
      xxp_payload_len += 4;
    else
      fputs("QWE -> RTYUIOP mangle FAILED\n", stderr);
  }                     /* if (tests[10] && (p = strstr(xxp_payload, "QWE"))) */

  if (tests[11] && (p = memmem(xxp_payload, xxp_payload_len, "ASD", 3)))
  {
    mangler(pktb, p - xxp_payload, 3, "G", 1);
    xxp_payload_len -= 2;
  }

  if (tests[12] && (p = memmem(xxp_payload, xxp_payload_len, "QWE", 3)))
  {
    if (mangler(pktb, p - xxp_payload, 3, "MNBVCXZ", 7))
    {
      xxp_payload_len += 4;
      if (!tests[19])
      {
        if (tests[13])
        {
          tcph = nfq_tcp_get_hdr(pktb);
          xxp_payload = nfq_tcp_get_payload(tcph, pktb);
        }                          /* if (tests[13]) */
        else
        {
          udph = nfq_udp_get_hdr(pktb);
          xxp_payload = nfq_udp_get_payload(udph, pktb);
        }                          /* if (tests[13]) else */
      }                            /* if (!tests[19]) */
    }                  /* if(mangler(pktb, p - xxp_payload, 3, "RTYUIOP", 7)) */
    else
      fputs("QWE -> MNBVCXZ mangle FAILED\n", stderr);
  }                     /* if (tests[12] && (p = strstr(xxp_payload, "QWE"))) */


  if (tests[17] && (p = memmem(xxp_payload, xxp_payload_len, "ZXC", 3)))
    mangler(pktb, p - xxp_payload, 3, "VBN", 3);

  if (tests[18] && (p = memmem(xxp_payload, xxp_payload_len, "ZXC", 3)))
    mangler(pktb, p - xxp_payload, 3, "VBN", 3);

send_verdict:
  nfq_send_verdict(ntohs(nfg->res_id), id, accept);

  if (!(tests[7] || tests[19] || tests[21]))
    pktb_free(pktb);

  return MNL_CB_OK;
}

/* ********************************** usage ********************************* */

static void
usage(void)
{
/* N.B. Trailing empty comments are there to stop gnu indent joining lines */
  puts("\nUsage: nfq6 [-a <alt q #>] " /*  */
    "[-t <test #>],... queue_number\n" /*  */
    "       nfq6 -h\n"             /*  */
    "  -a <n>: Alternate queue for test 4\n" /*  */
    "  -h: give this Help and exit\n" /*  */
    "  -t <n>: do Test <n>. Tests are:\n" /*  */
    "    0: If packet mark is zero, set it to 0xbeef and give verdict " /*  */
    "NF_REPEAT\n"                  /*  */
    "    1: If packet mark is not 0xfaceb00c, set it to that and give " /*  */
    "verdict NF_REPEAT\n"          /*  */
    "       If packet mark *is* 0xfaceb00c, give verdict NF_STOP\n" /*  */
    "    2: Allow ENOBUFS to happen; treat as harmless when it does\n" /*  */
    "    3: Configure NFQA_CFG_F_FAIL_OPEN\n" /*  */
    "    4: Send packets to alternate -a queue\n" /*  */
    "    5: Force on test 4 and specify BYPASS\n" /*  */
    "    6: Exit nfq6 if incoming packet starts \"q[:space:]\"" /*  */
    " (e.g. q\\r\\n)\n"            /*  */
    "    7: n/a\n"                 /*  */
    "    8: Use sendmsg to avoid memcpy after mangling\n" /*  */
    "    9: Replace 1st ASD by F\n" /*  */
    "   10: Replace 1st QWE by RTYUIOP\n" /*  */
    "   11: Replace 2nd ASD by G\n" /*  */
    "   12: Replace 2nd QWE by MNBVCXZ\n" /*  */
    "   13: Use TCP\n"             /*  */
    "   14: Report EINTR if we get it\n" /*  */
    "   15: Log netlink packets with no checksum\n" /*  */
    "   16: Log all netlink packets\n" /*  */
    "   17: Replace 1st ZXC by VBN\n" /*  */
    "   18: Replace 2nd ZXC by VBN\n" /*  */
#ifdef HAVE_PKTB_SETUP
    "   19: Use nfq_cb_run\n"      /*  */
#else
    "   19: n/a\n"                 /*  */
#endif
    "   20: Set 16MB kernel socket buffer\n" /*  */
#ifdef HAVE_PKTB_SETUP_RAW
    "   21: Use pktb_setup_raw\n"  /*  */
#else
    "   21: n/a\n"                 /*  */
#endif
    );
}                                  /* static void usage(void) */
