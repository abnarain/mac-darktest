#include <errno.h>
#include <error.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <math.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/wireless.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include "create-interface.h"
#include <fcntl.h>
static int create_ring(int in_fd,in_info *handle);
static void destroy_ring(int in_fd, in_info * handle);
static int  prepare_tpacket_socket(int in_fd, in_info* handle );
static int config_radio_interface(const char device[]);
static int up_radio_interface(const char device[]);
static int down_radio_interface(const char device[]);
static int open_infd(const char device[]);
static int setnonblock_mmap(in_info * handle);
static int iface_get_id(int fd, const char *device);
static int ind =0;
in_info handle[2];

u_int64_t timeval_to_int64(const struct timeval* tv)
{
  return (int64_t)(((u_int64_t)(*tv).tv_sec)* 1000000ULL + ((u_int64_t)(*tv).tv_usec));
}

static int config_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct iwreq    wrq;
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_name, device, IFNAMSIZ);
  wrq.u.mode = IW_MODE_MONITOR;
  if (0 > ioctl(sd, SIOCSIWMODE, &wrq)) {
    perror("ioctl(SIOCSIWMODE) \n");
    syslog(LOG_ERR, "ioctl(SIOCSIWMODE): %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

static int up_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  const int flags = IFF_UP|IFF_RUNNING|IFF_PROMISC;
  if (ifr.ifr_flags  == flags)
    return 0;
  ifr.ifr_flags = flags;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIFFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return -1;
  }  
  return 0;
}
static int down_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFLAGS)\n");
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  if (0 == ifr.ifr_flags)
    return 0;
  ifr.ifr_flags = 0;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIWMODE)\n");
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return -1;
  }
  return 0;
}


static int open_infd(const char device[])
{
  int skbsz ;
  skbsz = 1U << 23 ; 
  int in_fd ;
  in_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (in_fd < 0) {
    perror("socket(PF_PACKET)\n");
    return -1;
  }
  struct ifreq ifr;
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  
  if (0 > ioctl(in_fd, SIOCGIFINDEX, &ifr)) {
    perror("ioctl(SIOGIFINDEX)\n");
    return -1;
  }
  //printf("the ifindex of device is %d\n",ifr.ifr_ifindex);
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family  = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol= htons(ETH_P_ALL);
  if (0 > bind(in_fd, (struct sockaddr *) &sll, sizeof(sll))) {
    perror("bind()\n");
    return -1;
  }
  if (0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz, sizeof(skbsz))) {
    perror("setsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int skbsz_l = sizeof(skbsz);
  if (0 > getsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz,
		     (socklen_t*)&skbsz_l)) {
    perror("getsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int rcv_timeo = 600;
  struct timeval rto = { rcv_timeo, 0};
  if (rcv_timeo > 0 &&
      0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto))) {
    perror( "setsockopt(in_fd, SO_RCVTIMEO)\n");

    return -1;
  }
  return in_fd ;
}


int checkup(char * device){
  int in_fd ;
  if (down_radio_interface(device)){
    perror("down radio interface \n");
    return -1;
  }

  if (up_radio_interface(device)){
    perror("up radio interface \n");
    return -1;
  }
  
  if (config_radio_interface(device)){
    perror("config radio intereface ");
    return -1;
  }
  in_fd = open_infd(device);
  if(in_fd == -1){
    perror("Can't set socket option. Abort ");
    return -1;
  }

  
  memset(&handle[ind],'\0',sizeof(in_info));
  int retval ;
	handle[ind].lo_ifindex = iface_get_id(in_fd,"lo");  
  retval =activate_mmap(in_fd, &handle[ind]);
  if (retval != 1){
    fprintf(stderr, "Could not activate mmap \n");
    return -1;
  }
  setnonblock_mmap(&handle[ind]); 
  
  ind++;
  return in_fd;
}

int static drops=0; 
int k_pkt_stats(int in_fd)
{
  struct tpacket_stats kstats;
  socklen_t sl = sizeof (struct tpacket_stats);
  if (0 != getsockopt(in_fd, SOL_PACKET, PACKET_STATISTICS, &kstats, &sl)) {
    perror("getsockopt(PACKET_STATISTICS)\n");
    return 0;
  }
  if (0 == kstats.tp_drops)
    return 1;
  if(kstats.tp_drops >0) {
	fprintf( stderr, "#drops =%d \n", kstats.tp_drops-drops );
   }
  drops= kstats.tp_drops ;
/* not to use.. cause overhead 
  struct timeval now; 
  struct timeval _tstamp;
  gettimeofday(&now, NULL);
  int delay = -1000;
  if (0 == ioctl(in_fd, SIOCGSTAMP, &_tstamp)) {
    delay = timeval_to_int64(&now) - timeval_to_int64(&_tstamp);
  } else {
    perror("ioctl(SIOCGTSTAMP)\n");
  }
*/
  syslog( LOG_ERR,"last %d/%d blocks dropped, block delay is ms\n", kstats.tp_drops, kstats.tp_packets/* ,delay*/);
  return 1;
}

# ifdef TPACKET_HDRLEN
#  define HAVE_PACKET_RING 
#  ifdef TPACKET2_HDRLEN 
#   define HAVE_TPACKET2
#  else
#   define TPACKET_V1   0
#  endif /* TPACKET2_HDRLEN */
# endif /* TPACKET_HDRLEN */ 

#ifdef HAVE_PACKET_RING
#define RING_GET_FRAME(h) (((union thdr **)h->buffer)[h->offset])
#endif
#define PCAP_D_IN 1
#define PCAP_D_OUT 2

int activate_mmap(int in_fd, in_info* handle ){
  int ret;
  // Attempt to allocate a buffer to hold the contents of one packet, for use by the oneshot callback.
  handle->snapshot=8000; // mpdu is 7k+ for n packets 
  handle->oneshot_buffer = malloc(handle->snapshot);
  if (handle->oneshot_buffer == NULL) {
    printf("can't allocate oneshot buffer: %s",strerror(errno));
    return -1;
  }

  if (handle->buffer_size == 0) {
  //TODO:  by default request 1M for the ring buffer 
  printf("setting buffer size 1MB\n");
  handle->buffer_size = 1024*1024;
  }else{
  printf("handle buffer already set = %d \n",handle->buffer_size);
  }
  
  ret = prepare_tpacket_socket(in_fd, handle);
  if (ret != 1) {
    fprintf(stderr,"Can't prepare tpacket sockets  \n");
    free(handle->oneshot_buffer);
    return ret;
  }
  ret = create_ring(in_fd,handle);
  if (ret != 1) {
    fprintf(stderr, "Can't create ring \n");
    free(handle->oneshot_buffer);
    return ret;
  }
  return 1;
}

static int prepare_tpacket_socket(int in_fd, in_info* handle)
{
  socklen_t len;
  int val;
  handle->tp_version = TPACKET_V1;
  handle->tp_hdrlen = sizeof(struct tpacket_hdr);

  // Probe whether kernel supports TPACKET_V2 
  val = TPACKET_V2;
  len = sizeof(val);
  if (getsockopt(in_fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
    if (errno == ENOPROTOOPT){
      perror("Error: ENOPROTOOPT ; drive on \n");
      return 1;       // no - just drive on 
    }
    // Yes - treat as a failure. 
    perror("can't get TPACKET_V2 header len on packet socket\n");
    return -1;
  }
  handle->tp_hdrlen = val;
  val = TPACKET_V2;
  if (setsockopt(in_fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0) {
    perror("can't activate TPACKET_V2 on packet socket\n");
    return -1 ;
  }
  handle->tp_version = TPACKET_V2;
  return 1;
}

static int create_ring(int in_fd, in_info *handle)
{
  unsigned i, j, frames_per_block;
  struct tpacket_req req;

  //TODO: Note that with large snapshot (say 64K) only a few frames  will be available in the ring even with pretty 
  //large ring size (and a lot of memory will be unused). The snap len should be carefully chosen to achive best performance 
  req.tp_frame_size = TPACKET_ALIGN(handle->snapshot + TPACKET_ALIGN(handle->tp_hdrlen) + sizeof(struct sockaddr_ll));
  req.tp_frame_nr = handle->buffer_size/req.tp_frame_size;

  // compute the minumum block size that will handle this frame.  The block has to be page size aligned. 
  //  The max block size allowed by the kernel is arch-dependent and  it's not explicitly checked here. 
  req.tp_block_size = getpagesize();
  while (req.tp_block_size < req.tp_frame_size)
    req.tp_block_size <<= 1;
	
  frames_per_block = req.tp_block_size/req.tp_frame_size;
  // ask the kernel to create the ring 
 retry:
  req.tp_block_nr = req.tp_frame_nr / frames_per_block;

  // req.tp_frame_nr is requested to match frames_per_block*req.tp_block_nr 
  req.tp_frame_nr = req.tp_block_nr * frames_per_block;

  if (setsockopt(in_fd, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req))) {
    if ((errno == ENOMEM) && (req.tp_block_nr > 1)) {
      if (req.tp_frame_nr < 20)
	req.tp_frame_nr -= 1;
      else
	req.tp_frame_nr -= req.tp_frame_nr/20;
      goto retry;
    }
    if (errno == ENOPROTOOPT) {
     	perror("No support for ring buffer\n"); 
      return 0;
    }
    perror("Can't create rx ring on packet socket\n");
    return -1;
  }
  // memory map the rx ring 
  handle->mmapbuflen = req.tp_block_nr * req.tp_block_size;
  handle->mmapbuf = mmap(0, handle->mmapbuflen,PROT_READ|PROT_WRITE, MAP_SHARED, in_fd, 0);
  if (handle->mmapbuf == MAP_FAILED) {
    perror("Can't mmap rx ring\n");
    destroy_ring(in_fd,handle);
    return -1;
  }
  // allocate a ring for each frame header pointer
  handle->cc = req.tp_frame_nr;
  handle->buffer = malloc(handle->cc * sizeof(union thdr *));
  if (!handle->buffer) {
    printf("can't allocate ring of frame headers: %s", strerror(errno));
    destroy_ring(in_fd,handle);
    return -1;
  }
  // fill the header ring with proper frame ptr
  handle->offset = 0;
  for (i=0; i<req.tp_block_nr; ++i) {
    void *base = &handle->mmapbuf[i*req.tp_block_size];
    for (j=0; j<frames_per_block; ++j, ++handle->offset) {
      RING_GET_FRAME(handle) = base;
      base += req.tp_frame_size;
    }
  }
  handle->bufsize = req.tp_frame_size;
  handle->offset = 0;
  return 1;
}

// free all ring related resources
static void destroy_ring(int in_fd, in_info * handle )
{
  struct tpacket_req req;
  free(handle->oneshot_buffer);
  memset(&req, 0, sizeof(req));
  setsockopt(in_fd, SOL_PACKET, PACKET_RX_RING,(void *) &req, sizeof(req));
  // if ring is mapped, unmap it
  if (handle->mmapbuf) {
    // do not test for mmap failure, as we can't recover from any error 
    munmap(handle->mmapbuf, handle->mmapbuflen);
    handle->mmapbuf = NULL;
  }

}

static inline union thdr * get_ring_frame(in_info *handle, int status)
{
  union thdr h;
  h.raw = RING_GET_FRAME(handle);
  switch (handle->tp_version) {
  case TPACKET_V1:
    if (status != (h.h1->tp_status ? TP_STATUS_USER :  TP_STATUS_KERNEL))
      return NULL;
    break;
  case TPACKET_V2:
    if (status != (h.h2->tp_status ? TP_STATUS_USER : TP_STATUS_KERNEL))
      return NULL;
    break;
  }
  return h.raw;
}

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif
int read_mmap(int in_fd, in_info *handle, int max_packets, callback_handler callback, int interface ){
  int timeout;
  int pkts = 0;
  char c;

  // wait for frames availability
  if (!get_ring_frame(handle, TP_STATUS_USER)) {
    struct pollfd pollinfo;
    int ret;

    pollinfo.fd = in_fd;
    pollinfo.events = POLLIN;

    if (handle->timeout == 0)
      timeout = -1;   // block forever 
    else if (handle->timeout > 0)
      timeout = handle->timeout;   // block for that amount of time 
    else
      timeout = 0;    // non-blocking mode - poll to pick up errors 
    do {
      ret = poll(&pollinfo, 1, timeout);
      if (ret < 0 && errno != EINTR) {
	perror("Can't poll on packet socket\n");
	return -1;
      } else if (ret > 0 &&
		 (pollinfo.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {	
	// There's some indication other than "you can read on this descriptor" on the descriptor.
	 
	if (pollinfo.revents & (POLLHUP | POLLRDHUP)) {
	  fprintf(stderr,"Hangup on packet socket");
	  return -1;
	}
	if (pollinfo.revents & POLLERR) {	  
	  //  A recv() will give us the actual error code. XXX - make the socket non-blocking?	   
	  if (recv(in_fd, &c, sizeof c, MSG_PEEK) != -1)
	    continue;       // what, no error? 
	  if (errno == ENETDOWN) {	    
	    // The device on which we're capturing went away.
	    perror("The interface went down");
	  } else {
	    perror("Error condition on packet socket\n");
	  }
	  return -1;
	}
	if (pollinfo.revents & POLLNVAL) {
	  printf("Invalid polling request on packet socket");
	  return -1;
	}
      }
      //TODO: check for break loop condition on interrupted syscall
      if (handle->break_loop) {
	handle->break_loop = 0;
	return -1;
      }
    } while (ret < 0);
  }

  // non-positive values of max_packets are used to require all  packets currently available in the ring 
  while ((pkts < max_packets) || (max_packets <= 0)) {
    int run_bpf;
    struct sockaddr_ll *sll;
     pkthdr pkt_hdr;
    unsigned char *bp;
    union thdr h;
    unsigned int tp_len;
    unsigned int tp_mac;
    unsigned int tp_snaplen;
    unsigned int tp_sec;
    unsigned int tp_usec;
    h.raw = get_ring_frame(handle, TP_STATUS_USER);
    if (!h.raw)
      break;

    switch (handle->tp_version) {
    case TPACKET_V1:
      tp_len     = h.h1->tp_len;
      tp_mac     = h.h1->tp_mac;
      tp_snaplen = h.h1->tp_snaplen;
      tp_sec     = h.h1->tp_sec;
      tp_usec    = h.h1->tp_usec;
      break;
    case TPACKET_V2:
      tp_len     = h.h2->tp_len;
      tp_mac     = h.h2->tp_mac;
      tp_snaplen = h.h2->tp_snaplen;
      tp_sec     = h.h2->tp_sec;
      tp_usec    = h.h2->tp_nsec / 1000;
      break;
    default:
      fprintf(stderr,"unsupported tpacket version %d \n", handle->tp_version);
      return -1;
    }
    // perform sanity check on internal offset. 
    if (tp_mac + tp_snaplen > handle->bufsize) {
      fprintf(stderr,"corrupted frame on kernel ring mac " "offset %d + caplen %d > frame len %d\n", tp_mac, tp_snaplen, handle->bufsize);
      return -1;
    }

    // run filter on received packet. If the kernel filtering is enabled we need to run the
    // filter until all the frames present into the ring at filter creation time are processed. 
    // In such case md.use_bpf is used as a counter for the packet we need to filter.
    // Note: alternatively it could be possible to stop applying  the filter when the ring became empty, but it can possibly happen a lot later... 

    bp = (unsigned char*)h.raw + tp_mac;
#if 0
    run_bpf = (!handle->use_bpf) ||   ((handle->use_bpf>1) && handle->use_bpf--);
    if (run_bpf && handle->fcode.bf_insns &&(bpf_filter(handle->fcode.bf_insns, bp,tp_len, tp_snaplen) == 0))
      goto skip;
#endif 
    // Do checks based on packet direction.     
    sll = (void *)h.raw + TPACKET_ALIGN(handle->tp_hdrlen);
    if (sll->sll_pkttype == PACKET_OUTGOING) {
      // Outgoing packet. If this is from the loopback device, reject it; we'll see the packet as an incoming packet as well,
      // and we don't want to see it twice.
			printf("OUTGOIN\n");
      if (sll->sll_ifindex == handle->lo_ifindex){
				goto skip;      
			}
      // If the user only wants incoming packets, reject it.
      if (handle->direction == PCAP_D_IN){
				printf("in packets \n");
				goto skip;
			}
    } else {
      //Incoming packet. If the user only wants outgoing packets, reject it.
      if (handle->direction == PCAP_D_OUT){
				printf("out packets \n");
				goto skip;
			}
    }
    // get required packet info from ring header
    pkt_hdr.ts.tv_sec = tp_sec;
    pkt_hdr.ts.tv_usec = tp_usec;
    pkt_hdr.caplen = tp_snaplen;
    pkt_hdr.len = tp_len;

#if 0
    // if required build in place the sll header
    if (handle->md.cooked) {
      struct sll_header *hdrp;      
      // The kernel should have left us with enough space for an sll header; back up the packet
      // data pointer into that space, as that'll be the beginning of the packet we pass to the callback.       
      bp -= SLL_HDR_LEN;      
      // Let's make sure that's past the end of the tpacket header, i.e. >= ((u_char *)thdr + TPACKET_HDRLEN),
      // so we don't step on the header when we construct the sll header.       
      if (bp < (u_char *)h.raw +  TPACKET_ALIGN(handle->tp_hdrlen) +  sizeof(struct sockaddr_ll)) {
	fprintf(stderr,"cooked-mode frame doesn't have room for sll header");
	return -1;
      }

      // OK, that worked; construct the sll header.       
      hdrp = (struct sll_header *)bp;
      hdrp->sll_pkttype = map_packet_type_to_sll_type(
						      sll->sll_pkttype);
      hdrp->sll_hatype = htons(sll->sll_hatype);
      hdrp->sll_halen = htons(sll->sll_halen);
      memcpy(hdrp->sll_addr, sll->sll_addr, SLL_ADDRLEN);
      hdrp->sll_protocol = sll->sll_protocol;

      // update packet len 
      pcaphdr.caplen += SLL_HDR_LEN;
      pcaphdr.len += SLL_HDR_LEN;
    }
#endif 		
    // no need for vlan stuff ! 
    if (handle->tp_version == TPACKET_V2 && h.h2->tp_vlan_tci &&	tp_snaplen >= 2 * ETH_ALEN) {
      struct vlan_tag *tag;
      bp -= VLAN_TAG_LEN;
      memmove(bp, bp + VLAN_TAG_LEN, 2 * ETH_ALEN);
      tag = (struct vlan_tag *)(bp + 2 * ETH_ALEN);
      tag->vlan_tpid = htons(ETH_P_8021Q);
      tag->vlan_tci = htons(h.h2->tp_vlan_tci);
      pkt_hdr.caplen += VLAN_TAG_LEN;
      pkt_hdr.len += VLAN_TAG_LEN;
    }

    
     //The only way to tell the kernel to cut off the packet at a snapshot length is with a filter program;
     // if there's no filter program, the kernel won't cut the packet off.     
     // Trim the snapshot length to be no longer than the specified snapshot length.
     
    if (pkt_hdr.caplen > handle->snapshot)
      pkt_hdr.caplen = handle->snapshot;
    // pass the packet to the user 
    pkts++;
    callback(interface, &pkt_hdr, bp);
    handle->packets_read++;
  skip:
    // next packet 
    switch (handle->tp_version) {
    case TPACKET_V1:
      h.h1->tp_status = TP_STATUS_KERNEL;
      break;
    case TPACKET_V2:
      h.h2->tp_status = TP_STATUS_KERNEL;
      break;
    }
    if (++handle->offset >= handle->cc)
      handle->offset = 0;
    // check for break loop condition
    if (handle->break_loop) {
      handle->break_loop = 0;
      return -1;
    }
  }
  return pkts;
}



static int iface_get_id(int fd, const char *device)
{   
   struct ifreq    ifr;					    
   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
									    
   if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
   perror("SIOCGIFINDEX");
	   return -1;
	 } 
   return ifr.ifr_ifindex;
}


static int setnonblock_mmap(in_info * handle )
{
   // map each value to the corresponding 2's complement, to  preserve the timeout value provided with pcap_set_timeout 
    if (handle->timeout >= 0) {      
      //  Timeout is non-negative, so we're not already  in non-blocking mode; set it to the 2's
      //  complement, to make it negative, as an indication that we're in non-blocking mode.       
      handle->timeout = handle->timeout*-1 - 1;
    }
  
  return 0;
}


