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

typedef unsigned char uchar ;
  uchar jb[1600];
int create_header(int in_fd)
{
  const int jb_sz =  sizeof(jb);
  int jb_len = sizeof(jb);
	memset(&jb,'0',sizeof(jb));
	int r = recvfrom(in_fd, jb, jb_sz, MSG_TRUNC, NULL, NULL);
	if (r > jb_sz) {
		printf( "recvfrom: block is truncated (%d bytes), skip\n", r);
	//	continue;
	}
	if (r > 0) {
		jb_len= r;
		//      break;
	}
	if (0 == r) {
		printf("recvfrom returns 0 (%s), interface is down: bail\n", strerror(errno));
		return 1;
	}
	if (EAGAIN == errno) {
		printf("EAGAIN\n");
		//      return 1;
	}
	uchar* b=NULL;
	for(b = jb; b < jb+jb_len; ) {

	struct jigdump_hdr *jh = (struct jigdum_hdr *)b ;
	if(jh-> version_ == JIGDUMP_HDR_VERSION ){
        printf("version %d\n ",jh-> version_);
        printf("hdr_len %d \n ",jh-> hdrlen_);
        printf("status %d \n",jh-> status_);
        printf("phy-err %d \n",jh-> phyerr_);
        printf("rssi %d\n ",jh-> rssi_);
        printf("flags %d\n ",jh-> flags_);
        printf("channel %d\n ",jh-> channel_);
        printf("rate %d \n ",jh-> rate_);
        printf("caplen %d \n",jh-> caplen_);
        printf("snaplen %d \n ",jh-> snaplen_);
        printf("prev errs %d \n",jh-> prev_errs_);
        printf("mac time %llu \n",jh-> mac_time_);
        printf("fcs=%d\n",jh-> fcs_);

      }else{
        printf("Error : version not correct !  \n");
        printf("version %d\n ",jh-> version_);
        printf("phy-err %d \n",jh-> phyerr_);
        printf("rssi %d \n",jh-> rssi_);

      }
         b += sizeof(*jh) +jh->caplen_;
    }
	printf("I am out\n");

}

int main(int argc, char* argv[])
{
  char  *device0= argv[1];
  char  *device1= argv[2];
//  const int jb_sz =  sizeof(jb);
//  int jb_len = sizeof(jb);
  int t;
  int in_fd_0= checkup(device0);
  int in_fd_1= checkup(device1);
  printf("inside main");
  fd_set fd_wait; 
  struct timeval    st;
	

  for(;;)
  {
      FD_ZERO(&fd_wait);
      FD_SET(in_fd_0, &fd_wait);
      FD_SET(in_fd_1, &fd_wait);

      st.tv_sec  = 0;
      st.tv_usec = 200;
      t=select(FD_SETSIZE, &fd_wait, NULL, NULL, &st);
      switch(t)
        {
        case -1:  //omit case
          continue;
        case  0:
          break;
        default:
          if( FD_ISSET(in_fd_0, &fd_wait)) {
//            printf("I am in fd_0\n");
		 create_header(in_fd_0);

          }
          if( FD_ISSET(in_fd_1, &fd_wait)) {
//            printf("I am in fd_1\n");
		create_header(in_fd_1);
          }
        }
      // comes here when select times out or when a packet is processed
  }

    return 0 ;
}
