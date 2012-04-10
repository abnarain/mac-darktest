#ifndef _CREATE_INTERFACE_H_
#define _CREATE_INTERFACE_H_


#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include "td-util.h"
typedef struct {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
} pkthdr;

union thdr {
  struct tpacket_hdr      *h1;
  struct tpacket2_hdr     *h2;
  void                    *raw;
};


struct vlan_tag {
	 u_int16_t       vlan_tpid;              /* ETH_P_8021Q */
	 u_int16_t       vlan_tci;               /* VLAN TCI */
};

#define VLAN_TAG_LEN    4



// start of mmap 
typedef struct  {
  uchar* oneshot_buffer ; /*buffer for copy of packet */
  uchar *mmapbuf;       /* memory-mapped region pointer */
  uchar * buffer;
  size_t mmapbuflen;     /* size of region */
  unsigned int tp_version;     /* version of tpacket_hdr for mmaped ring */
  unsigned int tp_hdrlen;      /* hdrlen of tpacket_hdr for mmaped ring */
  int buffer_size;
	int break_loop;
  int bufsize;
	int direction;
  int snapshot;
  int cc ;
	int timeout;
  int offset ; 
	int lo_ifindex;
//	int use_bpf; // check for what its used ? 
	u_int packets_read ; // same here check
} in_info  ;
extern in_info handle[2];

typedef void (*callback_handler)(int, const pkthdr *, const uchar *);
int read_mmap(int in_fd, in_info *handle, int max_packets, callback_handler callback, int interface);
int activate_mmap(int in_fd, in_info* handle );

int checkup(char* device) ;
u_int64_t timeval_to_int64(const struct  timeval *tv);
int k_pkt_stats(int in_fd);




#endif

