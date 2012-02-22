#include <unistd.h>
#include <error.h>
#include <netinet/in.h>    
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/wireless.h>
#include <errno.h>
#include <math.h>
#include <pcap.h>
#include <ctype.h>
#include <inttypes.h>
#include "ieee80211_radiotap.h"
#include "td-util.h"
#include "create-interface.h"
#include "jigdump.h"
/* Set of signals that get blocked while processing a packet. */

struct pcap *pcap0=NULL;
struct pcap *pcap1=NULL;




static int sequence_number = 0;
#define cpack_int8(__s, __p)    cpack_uint8((__s),  (u_int8_t*)(__p))

int cpack_init(struct cpack_state *, u_int8_t *, size_t);
int cpack_uint8(struct cpack_state *, u_int8_t *);
int cpack_uint16(struct cpack_state *, u_int16_t *);
int cpack_uint32(struct cpack_state *, u_int32_t *);
int cpack_uint64(struct cpack_state *, u_int64_t *);

u_int8_t * cpack_next_boundary(u_int8_t *buf, u_int8_t *p, size_t alignment)
{
  size_t misalignment = (size_t)(p - buf) % alignment;

  if (misalignment == 0)
    return p;

  return p + (alignment - misalignment);
}

u_int8_t * cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize)
{
  u_int8_t *next;
  next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);
  if (next - cs->c_buf + wordsize > cs->c_len)
    return NULL;

  return next;
}

int cpack_uint32(struct cpack_state *cs, u_int32_t *u)
{
  u_int8_t *next;
  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;
  *u = EXTRACT_LE_32BITS(next);
  cs->c_next = next + sizeof(*u);
  return 0;
}
int cpack_uint16(struct cpack_state *cs, u_int16_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_16BITS(next);

  cs->c_next = next + sizeof(*u);
  return 0;
}


int cpack_uint8(struct cpack_state *cs, u_int8_t *u)
{

  if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
    return -1;

  *u = *cs->c_next;
  cs->c_next++;
  return 0;
}


int
cpack_init(struct cpack_state *cs, u_int8_t *buf, size_t buflen)
{
  memset(cs, 0, sizeof(*cs));

  cs->c_buf = buf;
  cs->c_len = buflen;
  cs->c_next = cs->c_buf;

  return 0;
}

int cpack_uint64(struct cpack_state *cs, u_int64_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;
  *u = EXTRACT_LE_64BITS(next);
  cs->c_next = next + sizeof(*u);
  return 0;
}
//#define MODE_DEBUG 0

int print_radiotap_field(struct cpack_state *s, u_int32_t bit, u_int8_t *flags)
{
  union {
    int8_t          i8;
    u_int8_t        u8;
    int16_t         i16;
    u_int16_t       u16;
    u_int32_t       u32;
    u_int64_t       u64;
  } u, u2, u3, u4;
  int rc;
  switch (bit) {
  case IEEE80211_RADIOTAP_FLAGS:
    rc = cpack_uint8(s, &u.u8);
    *flags = u.u8;
    break;
  case IEEE80211_RADIOTAP_RATE:
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
  case IEEE80211_RADIOTAP_ANTENNA:
    rc = cpack_uint8(s, &u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    rc = cpack_int8(s, &u.i8);
    break;
  case IEEE80211_RADIOTAP_CHANNEL:
    rc = cpack_uint16(s, &u.u16);
    if (rc != 0)
      break;
    rc = cpack_uint16(s, &u2.u16);
    break;
  case IEEE80211_RADIOTAP_FHSS:
  case IEEE80211_RADIOTAP_LOCK_QUALITY:
  case IEEE80211_RADIOTAP_TX_ATTENUATION:
    rc = cpack_uint16(s, &u.u16);
    break;
  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    rc = cpack_uint8(s, &u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_TX_POWER:
    rc = cpack_int8(s, &u.i8);
    break;
  case IEEE80211_RADIOTAP_TSFT:
    rc = cpack_uint64(s, &u.u64);
    break;
  case IEEE80211_RADIOTAP_XCHANNEL:
    rc = cpack_uint32(s, &u.u32);
    if (rc != 0)
      break;
    rc = cpack_uint16(s, &u2.u16);
    if (rc != 0)
      break;
    rc = cpack_uint8(s, &u3.u8);
    if (rc != 0)
      break;
    rc = cpack_uint8(s, &u4.u8);
    break;
  default:
    // this bit indicates a field whos size we do not know, so we cannot proceed.  Just print the bit number.     

    printf("[bit %u] ", bit);
 
    return -1;
  }
  if (rc != 0) {

    printf("[|802.11]");
 
    return rc;
  }

  switch (bit) {
  case IEEE80211_RADIOTAP_CHANNEL:
//    print_chaninfo(u.u16, u2.u16,paket);
    break;
  case IEEE80211_RADIOTAP_FHSS:

    printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
 
    break;
  case IEEE80211_RADIOTAP_RATE:
    if (u.u8 & 0x80){    
      printf(" got the mcs_rate %i\n", u.u8);
    }
    else{    
      u_int8_t _r= u.u8;
      printf("  %s%2.1f%s ", " ", (.5 * ((_r) & 0x7f)), " ");
    }
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
    printf("%ddB  signal ", u.i8);
    break;
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    printf("%ddB  noise ", u.i8);
    break;
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
    printf("%ddB signal ", u.u8);
    break;
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
    printf("%ddB noise ", u.u8);
    break;
  case IEEE80211_RADIOTAP_LOCK_QUALITY:
    printf("%u sq ", u.u16);
    break;
  case IEEE80211_RADIOTAP_TX_ATTENUATION:
    printf("%d tx power ", -(int)u.u16);
    break;
  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    printf("%ddB tx power ", -(int)u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_TX_POWER:
    break;
  case IEEE80211_RADIOTAP_FLAGS:
    if (u.u8 & IEEE80211_RADIOTAP_F_CFP){
      printf("cfp ");
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE){
      printf("short preamble ");
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_WEP){
      printf("wep "); 
  }
    if (u.u8 & IEEE80211_RADIOTAP_F_FRAG){
      printf("fragmented ");
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS){
      printf("bad-fcs ");
    }
    break;
  case IEEE80211_RADIOTAP_ANTENNA:
    printf("antenna %d ", u.u8);
    break;
  case IEEE80211_RADIOTAP_TSFT:
    //don't need it
    break;
  case IEEE80211_RADIOTAP_XCHANNEL:
    //print_chaninfo(u2.u16, u.u32,paket);
    break;
  }
  return 0;
}



u_int ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen)

{
#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)  (1U << n)
#define IS_EXTENDED(__p)        \
  (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

  struct cpack_state cpacker;
  struct ieee80211_radiotap_header *hdr;
  u_int32_t present, next_present;
  u_int32_t *presentp, *last_presentp;
  enum ieee80211_radiotap_type bit;
  int bit0;
  const u_char *iter;
  u_int len;
  u_int8_t flags;
  int pad;
  u_int fcslen;

  if (caplen < sizeof(*hdr)) {

    printf("caplen<hdr");
 
    return caplen;
  }
  hdr = (struct ieee80211_radiotap_header *)p;
  len = EXTRACT_LE_16BITS(&hdr->it_len);
  if (caplen < len) {
    printf("caplen<len"); 
    return caplen;
  }
  for (last_presentp = &hdr->it_present;
       IS_EXTENDED(last_presentp) &&
         (u_char*)(last_presentp + 1) <= p + len;
       last_presentp++);
  if (IS_EXTENDED(last_presentp)) {
    printf("more bitmap ext than bytes"); 
    return caplen;
  }
  iter = (u_char*)(last_presentp + 1);
  if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
    return caplen;
  }
  flags = 0;
  pad = 0;
  fcslen = 0;
  for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
       presentp++, bit0 += 32) {
    for (present = EXTRACT_LE_32BITS(presentp); present;
         present = next_present) {
      next_present = present & (present - 1);
      bit = (enum ieee80211_radiotap_type)
        (bit0 + BITNO_32(present ^ next_present));

      if (print_radiotap_field(&cpacker, bit, &flags) != 0)
        goto out;
    }
  }

  if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
    pad = 1;
  if (flags & IEEE80211_RADIOTAP_F_FCS)
    fcslen = 4;
 out:
 return len ; // ieee802_11_print(p + len, length - len, caplen - len, pad,fcslen);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}

typedef unsigned int uint;
void process_packet (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  //  snapend = packet+ header->caplen; 
  //ieee802_11_radio_print(packet, header->len, header->caplen);
  struct jigdump_hdr *jh = (struct jigdum_hdr *)packet ;
  printf("in main \n");
  printf("version %d\n ",jh-> version_);
  if(jh-> version_ ==99){
  printf("version %d\n ",jh-> version_);
  printf("hdr_len %d \n ",jh-> hdrlen_);
  printf("status %d \n",jh-> status_);
  printf("phy-err %d \n",jh-> phyerr_);
  printf("rssi %d\n ",jh-> rssi_);
  printf("flags %d\n ",jh-> flags_);
  printf("channel %d\n ",jh-> channel_);
  printf("rate %d\n ",jh-> rate_);

  printf("caplen %d \n",jh-> caplen_);
  printf("snaplen %d\n ",jh-> snaplen_);

  printf("rx delay %d\n ",jh-> rxdelay_); 
  printf("prev errs %d\n",jh-> prev_errs_);  
  printf("mac tsf%d\n",jh-> mac_tsf_);

  printf("mac time %d\n",jh-> mac_time_);
  printf("fcs=%d\n",jh-> fcs_);
  }else{
    printf("version %d\n ",jh-> version_);
    printf("phy-err %d \n",jh-> phyerr_);
    printf("packet is not having the required radiotap headers \n");
  }
}










int main(int argc, char* argv[])
{
  //setting the filter
  char *filter = "type mgt subtype beacon"; 
  int               t;
  fd_set            fd_wait;
  struct timeval    st;
  char              errbuf[PCAP_ERRBUF_SIZE];
  char              errbuf1[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;   
  bpf_u_int32 maskp;  
  struct bpf_program fp; 
  char  *device0= argv[1];
  char  *device1= argv[2];

  checkup(device0);
  checkup(device1);
  //declaring the two handles 
  pcap0 = pcap_open_live(device0, BUFSIZ, 1, -1, errbuf);
  pcap1 = pcap_open_live(device1, BUFSIZ, 1, -1, errbuf1);

  //setting the filter on phy0
 if (pcap_compile (pcap0, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "Compile: %s\n", pcap_geterr (pcap0));
      exit (1);
  }
  
  if (pcap_setfilter (pcap0, &fp) == -1){
    fprintf (stderr, "Setfilter: %s", pcap_geterr (pcap0));
    exit (1);
  }

  //setting the filter on phy1
 if (pcap_compile (pcap1, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "Compile: %s\n", pcap_geterr (pcap1)); 
      exit (1);
  }
  
  if (pcap_setfilter (pcap1, &fp) == -1){
    fprintf (stderr, "Setfilter: %s", pcap_geterr (pcap1)); 
    exit (1);
  }
  pcap_freecode (&fp); 
  //set them non blocking
  if(pcap_setnonblock(pcap0, 1, errbuf) == 1)
    {
      printf("Could not set device \"%s\" to non-blocking: %s\n", device0,errbuf);
      exit(1);
    }  
  
  if(pcap_setnonblock(pcap1, 1, errbuf) == 1){
      printf("Could not set device \"%s\" to non-blocking: %s\n", device1,errbuf1);
      exit(1);
    }

  
  for(;;)
    {
      FD_ZERO(&fd_wait);
      FD_SET(pcap_fileno(pcap0), &fd_wait);
      FD_SET(pcap_fileno(pcap1), &fd_wait);
      
      st.tv_sec  = 0;
      st.tv_usec = 500; 
      t=select(FD_SETSIZE, &fd_wait, NULL, NULL, &st);
      switch(t)
	{ 
	case -1:  //omit case
	  continue;
	case  0:
	  break;
	default:
	  if( FD_ISSET(pcap_fileno(pcap0), &fd_wait)) {
	    pcap_dispatch(pcap0,-1, (void *) process_packet, NULL);
	  }
	  if( FD_ISSET(pcap_fileno(pcap1), &fd_wait)) {
	    pcap_dispatch(pcap1,-1, (void *) process_packet, NULL);
	  }
	}
      // comes here when select times out or when a packet is processed
    }
    pcap_close (pcap0);
    pcap_close (pcap1);
    return 0 ;
}
