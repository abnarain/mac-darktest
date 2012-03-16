#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <netinet/in.h>    
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/wireless.h>
#include <math.h>
#include <ctype.h>
#include <inttypes.h>

#include "ieee80211.h"
#include "create-interface.h"
#include "jigdump.h"
#include "td-util.h"
#include "mgmt.h"
#include "pkts.h" 

u_int32_t pkt_count[2];
int j_hdr(struct jigdump_hdr *jh , int in_idx, struct rcv_pkt * paket){  
  if(jh->flags_ & RX_FLAG_HT)
    printf("is ht \n");
  if (jh->status_ & ATH9K_RXERR_PHY){
    printf("phy err \n");
    paket->ath_phy_err=1;
    exit(0);
  }
   printf("\n--\n");
  if (jh->status_ &  ATH9K_RXERR_CRC) {
    paket->ath_crc_err=1;
  } 
  paket->rssi=jh->rssi_;
  //  paket-> freq =jh->freq;
  paket-> antenna= jh->antenna_;
  paket->time=jh->mac_time_;
  //  printf("channel=%d freq=%d  antenna=%d \n",paket->channel, jh->channel_, paket->antenna);
  return 1;
}
int update_pkt(struct jigdump_hdr* jh, int pkt_len, int in_idx, struct rcv_pkt * paket){ 
  ++pkt_count[in_idx];
  struct mgmt_header_t *hp =NULL;
  struct ctrl_rts_t * rts = NULL;
  struct ctrl_cts_t *cts= NULL;
  struct ctrl_ack_t *ack =NULL;;
  uchar  * ptr2,* ptr ,* p;
  j_hdr(jh , in_idx, paket);
  struct  ieee80211_hdr* f = (struct ieee80211_hdr*)(jh+1) ; // sizeof(struct jigdump_hdr) ); 
  u_int16_t fc = EXTRACT_LE_16BITS(&f->frame_control);
  switch (FC_TYPE(fc)) {
  case MGT_FRAME:
    paket->pkt_type=MGT_FRAME;
    switch(FC_SUBTYPE(fc)){ 
    case ST_BEACON:
      hp = (struct mgmt_header_t *) (jh+ 1); //sizeof(struct jigdump_hdr));
      ptr= hp->sa;
      // printf(" beacon sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
      p = (uchar*) (jh+1) ;
      p+=   MGT_FRAME_HDR_LEN  ; 		
      handle_beacon(p, pkt_len, paket);
      break;
    case  ST_PROBE_REQUEST : 
      //      printf("response  sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
    case ST_PROBE_RESPONSE :
      hp = (struct mgmt_header_t *) (jh+ 1); // sizeof(struct jigdump_hdr));
      ptr= hp->sa;
      memcpy(paket->mac_address,hp->sa,6);
      p+= MGT_FRAME_HDR_LEN;
      //      memcpy(paket->p.mgmt_pkt.da,hp->sa,6);
      //      p = (uchar*) (jh+1) ;
      //      hp = (struct mgmt_header_t *) (jh+ 1); 
      //      ptr= hp->sa;
      //      printf("request sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);      
      break ;
    }
    break;
  case CONTROL_FRAME:
    paket->pkt_type= CONTROL_FRAME;
    switch(FC_SUBTYPE(fc)){ 
    case  CTRL_RTS :
     // printf("control frame %x\n",FC_SUBTYPE(fc));
      rts =  (struct ctrl_rts_t *) (jh+1) ; 
      memcpy(paket->mac_address,rts->ra,6);
      paket->p.ctrl_pkt.pkt_subtype = CTRL_RTS;
      memcpy(paket->p.ctrl_pkt.ta,rts->ta,6);
      uchar * a = paket->mac_address;
      uchar * t =paket->p.ctrl_pkt.ta;
     // printf(" rts ra: %02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
     // printf(" rts ta: %02x:%02x:%02x:%02x:%02x:%02x\n",t[0],t[1],t[2],t[3],t[4],t[5]);     
     break;
   case CTRL_CTS :
     cts=  (struct ctrl_cts_t * ) (jh+ 1); 
     paket->p.ctrl_pkt.pkt_subtype = CTRL_CTS;
     memcpy(paket->mac_address,cts->ra,6);
     ptr=paket->mac_address;
     //     printf(" cts ra: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
     break;
   case CTRL_ACKNOWLEDGEMENT :
     ack=  (struct ctrl_ack_t * ) (jh+1) ;
     paket->p.ctrl_pkt.pkt_subtype = CTRL_ACKNOWLEDGEMENT;
     memcpy(paket->mac_address,ack->ra,6);
     ptr=paket->mac_address;
     //     printf(" ack sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
     break;
   }
   break ;   
 case DATA_FRAME : {
   paket->pkt_type=DATA_FRAME;
   p= (uchar*)(jh+1);
   int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
   if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
     hdrlen += 2;
   // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
     if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
       memcpy(paket->mac_address,ADDR2,6);
       memcpy(paket->p.data_pkt.dst,ADDR2,6);
       //       printf("\n 1  src = %02x:%02x:%02x:%02x:%02x:%02x \n", ADDR2[0],ADDR2[1],ADDR2[2],ADDR2[3],ADDR2[4],ADDR2[5]);
       //       printf("1  dst =  %02x:%02x:%02x:%02x:%02x:%02x \n",ADDR1[0], ADDR1[1], ADDR1[2], ADDR1[3], ADDR1[4], ADDR1[5]);
     } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
       memcpy(paket->mac_address,ADDR3,6);
       memcpy(paket->p.data_pkt.dst,ADDR1,6);
       //       printf("\n 2 srcp =  %02x:%02x:%02x:%02x:%02x:%02x \n", ADDR3[0], ADDR3[1], ADDR3[2], ADDR3[3], ADDR3[4], ADDR3[5]); 
       //       printf("2 dstp =  %02x:%02x:%02x:%02x:%02x:%02x \n ", ADDR1[0], ADDR1[1], ADDR1[2], ADDR1[3], ADDR1[4], ADDR1[5]);
     } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
       memcpy(paket->mac_address,ADDR2,6);
       memcpy(paket->p.data_pkt.dst,ADDR3,6);
       //printf("\n 3 srcp =  %02x:%02x:%02x:%02x:%02x:%02x \n",ADDR2[0], ADDR2[1], ADDR2[2], ADDR2[3], ADDR2[4], ADDR2[5]); 
       //       printf(" 3 dstp = %02x:%02x:%02x:%02x:%02x:%02x\n ",ADDR3[0], ADDR3[1], ADDR3[2], ADDR3[3], ADDR3[4], ADDR3[5]);
     } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
       memcpy(paket->mac_address,ADDR4,6);
       memcpy(paket->p.data_pkt.dst,ADDR4,6);
       //       printf("\n 4 srcp =  %02x:%02x:%02x:%02x:%02x:%02x \n",ADDR4[0], ADDR4[1], ADDR4[2], ADDR4[3], ADDR4[4], ADDR4[5]); 
       //       printf(" 4 dstp=  %02x:%02x:%02x:%02x:%02x:%02x\n",ADDR3[0], ADDR3[1], ADDR3[2], ADDR3[3], ADDR3[4], ADDR3[5]); 
#undef ADDR4
     }
#undef ADDR1
#undef ADDR2
#undef ADDR3   
     handle_data(fc,p,hdrlen,paket);
 }
   break;
default :
   paket->pkt_type= 0x3;
  printf("none type \n");   
 } 

 return 1; 
 
}

int create_header(uchar *jb, const int jb_len, int in_idx){
  uchar* b=NULL;
  for(b = jb; b < jb+ jb_len; ) {
    struct jigdump_hdr *jh = (struct jigdump_hdr *)b ;
    if(jh-> version_ != JIGDUMP_HDR_VERSION ){
      syslog(LOG_ERR,"invalid jigdump_hdr (v=%u) snaplen=%u, discard\n",   (uint)jh->version_,  jh->snaplen_);
      return 0;
    }
    if (jh->hdrlen_ != sizeof(*jh)) {
      syslog(LOG_ERR," jigdump hdr_len %d mis-match (%d), discard\n", (int)jh->hdrlen_, (int)sizeof(*jh));
      return 0;
    }
   // test_func_inspection (jh);	
    //TODO: check for channel here ! when you get better
    b += sizeof(*jh) + jh->snaplen_ ;
    if (b > jb + jb_len) {
      syslog( LOG_ERR,"data is mis-aligned %d:%d, caplen=%d discard block\n", (int)(b-jb), jb_len, jh->snaplen_);
      return 0;
    }
    struct rcv_pkt paket ;
    memset(&paket,0, sizeof(struct rcv_pkt));
    update_pkt(jh, jb_len, in_idx, &paket);
  }
  //  printf("I am out\n");
  return 1;
}

int rcv_timeo=-1;

int read_raw_socket(int in_fd, uchar*jb, int *jb_len,int in_idx){
  const int jb_sz = *jb_len;  
  int timeout=0,r=0;
  for(timeout=0;;){
    *jb_len=0;
    r = recvfrom(in_fd, jb, jb_sz, MSG_TRUNC, NULL, NULL);
    if (r > jb_sz) {
     printf( stderr,"recvfrom: block is truncated (%d bytes), skip\n", r);
      continue;
    }
    if (r > 0) {
      *jb_len= r;
      break;
    }
    if (0 == r) {
      perror("Interface is down: bail\n");
      return 0;
    }
    if (EAGAIN == errno) {
      perror("EAGAIN \n");
      //XXX :check for writing into int descriptor
      if ((++timeout)*rcv_timeo >= 600) { //~10 min
	printf(stderr, "recvfrom timeout %d times, abort\n", timeout);
	return 0;
      }  
    }else if (errno !=0){
      perror("Error");
      return 0;
    }
  }
  return 1;
}
int capture_(int in_fd, int in_idx)
{
  uchar jb[JIGBLOCK_MAX_SIZE];
  int jb_len= sizeof(jb);
  int ok=0 ;
  ok=read_raw_socket(in_fd,jb, &jb_len,in_idx );
  if(ok){
  create_header(jb,jb_len, in_idx); 
  }else{
  printf("cant\n");
  }
   if(pkt_count[in_idx]%500){
	k_pkt_stats(in_fd);
   }
  return 1;
}

int main(int argc, char* argv[])
{
  char  *device0= argv[1];
  char  *device1= argv[2];
  int t;
  int in_fd_0= checkup(device0);
  int in_fd_1= checkup(device1);
  fd_set fd_wait; 
  struct timeval st;
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
	    capture_(in_fd_0,0);
          }
          if( FD_ISSET(in_fd_1, &fd_wait)) {
	    capture_(in_fd_1,1);
          }
        }
      // comes here when select times out or when a packet is processed
    }
    return 0 ;
}
