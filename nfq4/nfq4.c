/* N F Q 4 */

/* System headers */

#define _GNU_SOURCE                /* To get memmem */
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
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>

/* Macros */

#define NUM_TESTS 21

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

/* Static Variables */

static struct mnl_socket *nl;
/* Largest possible packet payload, plus netlink data overhead: */
static char nlrxbuf[0xffff + 4096];
static char nltxbuf[sizeof nlrxbuf];
static struct pkt_buff *pktb;
static bool tests[NUM_TESTS] = { false };

static uint32_t packet_mark;
static int alternate_queue;
static bool quit;
static socklen_t wanted_size = 1024 * 1024 * 8;
static socklen_t socklen = sizeof wanted_size, read_size;
static struct sockaddr_nl snl = {.nl_family = AF_NETLINK };


/* Static prototypes */

static void usage(void);
static int queue_cb(const struct nlmsghdr *nlh, void *data);
static void nfq_send_verdict(int queue_num, uint32_t id, bool accept);

/* **************************** nfq_send_verdict **************************** */

static void
nfq_send_verdict(int queue_num, uint32_t id, bool accept)
{
  struct nlmsghdr *nlh;
  bool done = false;

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_VERDICT, queue_num);

  if (!accept)
  {
    nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
    goto send_verdict;
  }

  if (tests[0] && !packet_mark)
  {
    nfq_nlmsg_verdict_put_mark(nlh, 0xbeef);
    nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    done = true;
  }

  if (tests[1] && !done)
  {
    if (packet_mark == 0xfaceb00c)
    {
      nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
    }
    else
    {
      nfq_nlmsg_verdict_put_mark(nlh, 0xfaceb00c);
      nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    }
    done = true;
  }

  if (tests[4] && !done)
  {
    nfq_nlmsg_verdict_put(nlh, id,
      NF_QUEUE_NR(alternate_queue) |
      (tests[5] ? NF_VERDICT_FLAG_QUEUE_BYPASS : 0));
    done = true;
  }

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
    };

    attrib->nla_type = NFQA_PAYLOAD;
    attrib->nla_len = sizeof(struct nlattr) + len;
    nlh->nlmsg_len += sizeof(struct nlattr);
    iov[0].iov_base = nlh;
    iov[0].iov_len = nlh->nlmsg_len;
    iov[1].iov_base = pktb_data(pktb);
    iov[1].iov_len = len;
    nlh->nlmsg_len += len;
    if (sendmsg(mnl_socket_get_fd(nl), &msg, 0) < 0)
    {
      perror("sendmsg");
      exit(EXIT_FAILURE);
    }
  }
  else
  {
    if (pktb_mangled(pktb))
      nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
  send_verdict:
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_sendto");
      exit(EXIT_FAILURE);
    }
  }
  if (quit)
    exit(0);
}

/* ******************************** queue_cb ******************************** */

#ifdef GIVE_UP
#undef GIVE_UP
#endif
#define GIVE_UP(x)\
do {fputs(x, stderr); goto send_verdict; } while (0)

#ifdef GIVE_UP2
#undef GIVE_UP2
#endif
#define GIVE_UP2(x, y)\
do {fprintf(stderr, x, y); goto send_verdict; } while (0)

static int
queue_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nfqnl_msg_packet_hdr *ph = NULL;
  uint32_t id = 0, skbinfo;
  struct nfgenmsg *nfg;
  uint8_t *payload;
  uint8_t *udp_payload;
  unsigned int udp_payload_len;
  bool accept = true;
  static struct udphdr *udph;
  static struct iphdr *ip4h;
  char erbuf[4096];
  bool normal = !tests[16];        /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  uint16_t plen;
  uint8_t *p;
  struct nlattr *attr[NFQA_MAX + 1] = { };
  char *errfunc;
  char pb[pktb_head_size()];

  if (nfq_nlmsg_parse(nlh, attr) < 0)
  {
    perror("problems parsing");
    return MNL_CB_ERROR;
  }

/* Most of the lines in this next block are individually annotated in
 * nf-queue.c.
 */
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
    }
  }

  if (skbinfo & NFQA_SKB_GSO)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc, "%s", "GSO ");
    normal = false;
  }

  id = ntohl(ph->packet_id);
  nc += snprintf(record_buf + nc, sizeof record_buf - nc, "packet "
    "received (id=%u hw=0x%04x hook=%u, payload len %u",
    id, ntohs(ph->hw_protocol), ph->hook, plen);

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
  }
  if (!normal)
    printf("%s)\n", record_buf);

/* Set up a packet buffer. If copying data, allow 255 bytes extra room;
 * otherwise use extra room in the receive buffer.
 * AF_INET6 and AF_INET work the same, no need to look at true.
 */
#define EXTRA 255
  if (tests[7])
  {
    pktb = pktb_setup_raw(pb, AF_INET6, payload, plen, *(size_t *)data);
    errfunc = "pktb_setup_raw";
  }
  else
  {
    pktb = pktb_alloc(AF_INET6, payload, plen, EXTRA);
    errfunc = "pktb_alloc";
  }
  if (!pktb)
  {
    snprintf(erbuf, sizeof erbuf, "%s. (%s)\n", strerror(errno), errfunc);
    GIVE_UP(erbuf);
  }

  if (!(ip4h = nfq_ip_get_hdr(pktb)))
    GIVE_UP2("Malformed IPv%c\n", true ? '4' : '6');

  if (nfq_ip_set_transport_header(pktb, ip4h))
    GIVE_UP("No payload found\n");
  if (!(udph = nfq_udp_get_hdr(pktb)))
    GIVE_UP2("Packet too short to get %s header\n", "UDP");
  if (!(udp_payload = nfq_udp_get_payload(udph, pktb)))
    GIVE_UP2("Packet too short to get %s payload\n", "UDP");
  udp_payload_len = nfq_udp_get_payload_len(udph, pktb);

  if (tests[6] && udp_payload_len >= 2 && udp_payload[0] == 'q' &&
    isspace(udp_payload[1]))
  {
    accept = false;                /* Drop this packet */
    quit = true;                   /* Exit after giving verdict */
  }

  if (tests[9] && (p = memmem(udp_payload, udp_payload_len, "ASD", 3)))
  {
    nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "F", 1);
    udp_payload_len -= 2;
  }

  if (tests[10] && (IPPROTO_UDP == IPPROTO_UDP || tests[19]) &&
    (p = memmem(udp_payload, udp_payload_len, "QWE", 3)))
  {
    if (nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "RTYUIOP", 7))
      udp_payload_len += 4;
    else
      fputs("QWE -> RTYUIOP mangle FAILED\n", stderr);
  }

  if (tests[11] && (p = memmem(udp_payload, udp_payload_len, "ASD", 3)))
  {
    nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "G", 1);
    udp_payload_len -= 2;
  }


  if (tests[12] && (IPPROTO_UDP == IPPROTO_UDP || tests[19]) &&
    (p = memmem(udp_payload, udp_payload_len, "QWE", 3)))
  {
    if (nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "MNBVCXZ", 7))
      udp_payload_len += 4;
    else
      fputs("QWE -> MNBVCXZ mangle FAILED\n", stderr);
  }

  if (tests[17] && (p = memmem(udp_payload, udp_payload_len, "ZXC", 3)))
    nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "VBN", 3);

  if (tests[18] && (p = memmem(udp_payload, udp_payload_len, "ZXC", 3)))
    nfq_udp_mangle_ipv4(pktb, p - udp_payload, 3, "VBN", 3);

send_verdict:
  nfq_send_verdict(ntohs(nfg->res_id), id, accept);

  if (!tests[7])
    pktb_free(pktb);

  return MNL_CB_OK;
}

/* ********************************** main ********************************** */

int
main(int argc, char *argv[])
{
  struct nlmsghdr *nlh;
  int ret;
  unsigned int portid, queue_num;
  int i;
  size_t sperrume;                 /* Spare room */

  while ((i = getopt(argc, argv, "a:ht:")) != -1)
  {
    switch (i)
    {
      case 'a':
        alternate_queue = atoi(optarg);
        if (alternate_queue <= 0 || alternate_queue > 0xffff)
        {
          fprintf(stderr,
            "Alternate queue number %d is out of range\n", alternate_queue);
          exit(EXIT_FAILURE);
        }
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
        }
        tests[ret] = true;
        break;

      case '?':
        exit(EXIT_FAILURE);
    }
  }

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
  }

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

  if (tests[13])
  {
    if (setsockopt
      (mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUFFORCE,
      &wanted_size, sizeof(socklen_t)) == -1)
      fprintf(stderr, "%s. setsockopt SO_RCVBUFFORCE 0x%x\n",
        strerror(errno), wanted_size);
  }
  getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUF, &read_size,
    &socklen);
  printf("Read buffer set to 0x%x bytes (%dMB)\n", read_size,
    read_size / (1024 * 1024));

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_UNSPEC, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_nlmsg_put(nltxbuf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  if (!tests[20] || tests[3])
  {
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS,
      htonl((tests[20] ? 0 : NFQA_CFG_F_GSO) |
      (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));
  }
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
  {
    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));
  }

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
    sperrume = sizeof nlrxbuf - ret;

    ret = mnl_cb_run(nlrxbuf, ret, 0, portid, queue_cb, &sperrume);
    if (ret < 0 && (errno != EINTR || tests[14]))
    {
      perror("mnl_cb_run");
      if (errno != EINTR)
        exit(EXIT_FAILURE);
    }
  }

  mnl_socket_close(nl);

  return 0;
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
    "    0: If packet mark is zero, set it to 0xbeef and give verdict " /* */
    "NF_REPEAT\n"                  /*  */
    "    1: If packet mark is not 0xfaceb00c, set it to that and give " /* */
    "verdict NF_REPEAT\n"          /*  */
    "       If packet mark *is* 0xfaceb00c, accept the packet\n" /* */
    "    2: Allow ENOBUFS to happen; treat as harmless when it does\n" /* */
    "    3: Configure NFQA_CFG_F_FAIL_OPEN\n" /* */
    "    4: Send packets to alternate -a queue\n" /*  */
    "    5: Force on test 4 and specify BYPASS\n" /*  */
    "    6: Exit nfq6 if incoming packet starts \"q[:space:]\"" /* */
    " (e.g. q\\n)\n"               /*  */
    "    7: Use pktb_setup_raw\n"  /*  */
    "    8: Use sendmsg to avoid memcpy after mangling\n" /*  */
    "    9: Replace 1st ASD by F\n" /*  */
    "   10: Replace 1st QWE by RTYUIOP (UDP packets only)\n" /* */
    "   11: Replace 2nd ASD by G\n" /* */
    "   12: Replace 2nd QWE by MNBVCXZ (UDP packets only)\n" /* */
    "   13: Set 16MB kernel socket buffer\n" /* */
    "   14: Report EINTR if we get it\n" /*  */
    "   15: Log netlink packets with no checksum\n" /* */
    "   16: Log all netlink packets\n" /* */
    "   17: Replace 1st ZXC by VBN\n" /*  */
    "   18: Replace 2nd ZXC by VBN\n" /*  */
    "   19: Enable tests 10 & 12 for TCP (not recommended)\n" /* */
    "   20: Disable GSO\n"         /*  */
    );
}
