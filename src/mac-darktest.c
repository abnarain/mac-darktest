#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <zlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <syslog.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include<net/if.h>

#include "ieee80211.h"
#include "create-interface.h"
#include "jigdump.h"
#include "td-util.h"
#include "mgmt.h"
#include "pkts.h" 
#include "address_table.h"
#include "nl_funcs.h"

#define UPDATE_PERIOD_SECS 60
#define NUM_MICROS_PER_SECOND 1e6

unsigned char * snapend; 
sigset_t block_set;
struct timeval start_timeval;
u_int32_t pkt_count[2];
static int prev_phy_err_1;
static int prev_phy_err_0;

int j_hdr(struct jigdump_hdr *jh , int in_idx, struct rcv_pkt * paket){  

  paket->rssi=jh->rssi_;
  paket-> antenna= jh->antenna_;
  paket-> freq = jh->freq_ ;
  //  printf("timestamp= %"PRIu64 "\n", paket->timestamp);
  //  printf("antenna=%d  \n", paket->antenna);
  //  printf("rssi=%d\n",paket->rssi);
  //TODO: What to do with all these flags ? save or discard ?

  if(jh->flags_ & RX_FLAG_HT ){	
    printf(" !!!!!!! IS HT  \n");
    u_int8_t _r = jh->rate_idx_ ;
    if (_r & 0x80){
    paket->rate=  (.5 * ieee80211_htrates[(_r) & 0xf]);
    printf("rate idx =%f \n",paket->rate);
    }
  }else {
    paket->rate =   (float)((.5 * ((jh->rate_) & 0x7f)));
  }

  if(jh->flags_ &  RX_FLAG_SHORT_GI ){	
    printf(" !!!!!!! IS short GI  \n");
  }
  if(jh->flags_ & RX_FLAG_SHORTPRE ){	
    paket->short_preamble_err=1;
    printf(" !!!!!!! IS SHORT PRE  \n");
  }
  if(jh->flags_ & RX_FLAG_40MHZ ){
    printf(" !!!!!!! IS 40   \n");
  }
  
  // in_idx ??  printf("phy err %u \n", jh->status_ );
  if(jh->antenna_ ==0){
    paket->ath_phy_err= jh->phyerr_ - prev_phy_err_0;
     prev_phy_err_0 =jh->phyerr_ ;
     
  }else  {
    paket->ath_phy_err= jh->phyerr_ - prev_phy_err_1;
    prev_phy_err_1 =jh->phyerr_ ;
	
  }
  //    printf("interface= %d phy_cnt= %u \n",in_idx,paket->ath_phy_err);
  
  if (jh->flags_ & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC )) {
    paket->ath_crc_err=1;
  }
  int flags = jh->channel_;
  if (IS_CHAN_FHSS(flags)){
     paket->channel_rcv=1;
  }
  if (IS_CHAN_A(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
     paket->channel_rcv=3;
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
     paket->channel_rcv=4;
    }
    else{
     paket->channel_rcv=2;//a
    }
  }
  if (IS_CHAN_ANYG(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
     paket->channel_rcv=7;
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
     paket->channel_rcv=8;
    }
    else{
     paket->channel_rcv=6;//g
    }
  } else if (IS_CHAN_B(flags)){
    paket->channel_rcv=5;//b
  }
  if (flags & IEEE80211_CHAN_TURBO){
     paket->channel_rcv=9;
  }
  if (flags & IEEE80211_CHAN_HT20){
     paket->channel_rcv=10;
  }
  else if (flags & IEEE80211_CHAN_HT40D){
     paket->channel_rcv=11;
  }
  else if (flags & IEEE80211_CHAN_HT40U){
     paket->channel_rcv=12;
  } 
//   printf("--\n");
   return 1;
}

int update_pkt(struct jigdump_hdr* jh, int pkt_len, int in_idx, struct rcv_pkt * paket){ 
  if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }
  ++pkt_count[in_idx];
  snapend = (uchar *)(jh+jh->caplen_) ;
  
  struct mgmt_header_t *hp =NULL;
  struct ctrl_rts_t * rts = NULL;
  struct ctrl_cts_t *cts= NULL;
  struct ctrl_ack_t *ack =NULL;;
  uchar  * ptr2,* ptr ,* p, *none;
  j_hdr(jh , in_idx, paket);
  struct  ieee80211_hdr* f = (struct ieee80211_hdr*)(jh+1) ;
  u_int16_t fc = EXTRACT_LE_16BITS(&f->frame_control);
  if (FC_MORE_DATA(fc))
    paket->more_data =1;
  if (FC_MORE_FLAG(fc))
    paket->more_flag =1;
  if (FC_ORDER(fc))
    paket->strictly_ordered=1;
  if (FC_RETRY(fc))
    paket->retry=1;
  if (FC_WEP(fc))
    paket->wep_enc=1;
  
  switch (FC_TYPE(fc)) {
  case MGT_FRAME:
    paket->pkt_type=MGT_FRAME;
    switch(FC_SUBTYPE(fc)){ 
    case ST_BEACON:
      hp = (struct mgmt_header_t *) (jh+ 1); 
      memcpy(paket->mac_address,hp->sa,6);
      ptr= hp->sa;
      // printf(" beacon sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
      p = (uchar*) (jh+1) ;
      p+=   MGT_FRAME_HDR_LEN  ;
      paket->p.mgmt_pkt.pkt_subtype=ST_BEACON;		
      handle_beacon(p, pkt_len, paket);
      address_mgmt_table_lookup(&mgmt_address_table,paket);
      //ptr=paket->mac_address;
      //printf(" beacon sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
   
      break;
    case  ST_PROBE_REQUEST : 
//      hp = (struct mgmt_header_t *) (jh+ 1);
  //    ptr= hp->sa;
    //        printf("response  sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
    case ST_PROBE_RESPONSE :
      paket->p.mgmt_pkt.pkt_subtype=ST_PROBE_RESPONSE;		
      hp = (struct mgmt_header_t *) (jh+ 1);
      ptr= hp->sa;
      memcpy(paket->mac_address,hp->sa,6);
     // memcpy(paket->p.mgmt_pkt.da,hp->sa,6);
      address_mgmt_table_lookup(&mgmt_address_table,paket);
/*
      ptr= hp->sa;

     printf("request sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);      
	      
      p = (uchar*) (jh+1) ;
     int idx=0;
     for(idx=0;idx<20;idx++)
       printf("%02x ",*(p+idx));
*/
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
      address_control_table_lookup(&control_address_table,paket);
     // uchar * a = paket->mac_address;
     // uchar * t =paket->p.ctrl_pkt.ta;
     // printf(" rts ra: %02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
     // printf(" rts ta: %02x:%02x:%02x:%02x:%02x:%02x\n",t[0],t[1],t[2],t[3],t[4],t[5]);     
     break;
   case CTRL_CTS :
     cts=  (struct ctrl_cts_t * ) (jh+ 1); 
     paket->p.ctrl_pkt.pkt_subtype = CTRL_CTS;
     memcpy(paket->mac_address,cts->ra,6);
     address_control_table_lookup(&control_address_table,paket);
   //  ptr=paket->mac_address;
   //  printf(" cts ra: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
     break;
   case CTRL_ACKNOWLEDGEMENT :
     ack=  (struct ctrl_ack_t * ) (jh+1) ;
     paket->p.ctrl_pkt.pkt_subtype = CTRL_ACKNOWLEDGEMENT;
     memcpy(paket->mac_address,ack->ra,6);
     address_control_table_lookup(&control_address_table,paket);
  // ptr=paket->mac_address;
  // printf(" ack sa: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
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
       memcpy(paket->p.data_pkt.dst,ADDR1,6);
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
/*
     int idx=0;
     for(idx=0;idx<40;idx++)
       printf("%02x ",*(p+idx));
     printf("going to handle_data()\n");
*/
     handle_data(fc,p,hdrlen,paket); //pass caplen for later checks
     address_data_table_lookup(&data_address_table,paket);
 }
   break;
default :
   paket->pkt_type= 0x3;   
  
   memcpy(paket->mac_address,f->addr1,6);
   ptr=paket->mac_address;
   //printf(" none addr: %02x:%02x:%02x:%02x:%02x:%02x\n",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);

//   address_none_table_lookup(&none_address_table,paket);
//   printf("none type  %d \n",paket->ath_crc_err);

  }
  //TODO: add the logging capability 
  if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }
  return 1;  
}

int create_header(uchar *jb, const int jb_len, int in_fd, int in_idx, struct timeval * ts ){
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
      syslog(LOG_ERR,"data is mis-aligned %d:%d, caplen=%d discard block\n", (int)(b-jb), jb_len, jh->snaplen_);

      return 0;
    }
    struct rcv_pkt paket ;
    memset(&paket,0, sizeof(struct rcv_pkt));
    paket.timestamp = ts->tv_sec * NUM_MICROS_PER_SECOND + ts->tv_usec;
    update_pkt(jh, jb_len, in_idx, &paket);
  }
  //  printf("I am out\n");
  return 1;
}

int rcv_timeo=-1;

int read_raw_socket( uchar*jb, int *jb_len, int in_fd, struct timeval * ts){
  const int jb_sz = *jb_len;  
  int timeout,rcv_bytes=0;
  for(timeout=0;;){
    *jb_len=0;
    rcv_bytes = recvfrom(in_fd, jb, jb_sz, MSG_TRUNC, NULL, NULL);
    if (rcv_bytes > jb_sz) {
     fprintf( stderr,"recvfrom: block is truncated (%d bytes), skip\n", rcv_bytes);
      continue;
    }
    if (rcv_bytes > 0) {
      *jb_len= rcv_bytes;
      break;
    }
    if (0 == rcv_bytes) {
      perror("Interface is down: bail out\n");
      return 1;
    }
    if (EAGAIN == errno) {
      perror("EAGAIN \n");
      //XXX :check for writing into int descriptor; pcap(4.1.1)  doesn't do it ... should I ? 
      if ((++timeout)*rcv_timeo >= 600) { //~10 min
	fprintf(stderr, "recvfrom timeout %d times, abort\n", timeout);
	return 1;
      }  
    }else if (errno !=0){
      perror("Error");
      return 1;
    }
  }
  if (ioctl(in_fd, SIOCGSTAMP, ts) == -1) {
	perror("SIOCGSTAMP \n");
        return 1;
  }

  return 0;
}

int capture_(int in_fd, int in_idx)
{
  uchar jb[JIGBLOCK_MAX_SIZE];
  struct timeval ts;
  int jb_len= sizeof(jb);
  int ok=0 ;
  ok=read_raw_socket(jb, &jb_len,in_fd, &ts );
  if(!ok){
  create_header(jb,jb_len, in_fd, in_idx, &ts); 
  }else{
  perror("read_raw_socket failed \n");
  }
   if(pkt_count[in_idx]%500){
     k_pkt_stats(in_fd);
   }
   //   printf("in capture\n");
  return 1;
}

void set_next_alarm() {
 alarm(UPDATE_PERIOD_SECS);
}

void handle_signals(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    write_update();
    exit(0);
  } else if (sig == SIGALRM) {
    write_update();
    set_next_alarm();
  }
}

void initialize_signal_handler() {
  struct sigaction action;
  action.sa_handler = handle_signals;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  if (sigaction(SIGINT, &action, NULL) < 0
      || sigaction(SIGTERM, &action, NULL) < 0
      || sigaction(SIGALRM, &action, NULL)) {
    perror("sigaction");
    exit(1);
  }
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGALRM);
}

int main(int argc, char* argv[])
{
  initialize_bismark_id();
  address_data_table_init(&data_address_table);
  address_mgmt_table_init(&mgmt_address_table);
  address_control_table_init(&control_address_table);
  gettimeofday(&start_timeval, NULL);
  start_timestamp_microseconds  = start_timeval.tv_sec * NUM_MICROS_PER_SECOND + start_timeval.tv_usec;

  //setting the signal
  initialize_signal_handler();
  set_next_alarm();

  char  *device0= argv[1];
  char  *device1= argv[2];
  int retval;
  int in_fd_0= checkup(device0);
  int in_fd_1= checkup(device1);
  fd_set fd_wait; 
  printf("in main\n");
  struct timeval st;
  int err_0, err_1, fd_0, fd_1 ,devidx_0 = 0, devidx_1=0;
  devidx_0 = if_nametoindex("wlan0");
  devidx_1 = if_nametoindex("wlan1");

  for(;;)
    {
/* 
   struct nl80211_state nlstate_0, nlstate_1;
    struct nl_cb *cb_0,*cb_1;
    struct nl_cb *s_cb_0, *s_cb_1;
    struct nl_msg *msg_0, *msg_1;
    err_0 = nl80211_init(&nlstate_0);
    err_1 = nl80211_init(&nlstate_1);
    if (err_1 || err_0)
      return -1;
    msg_0 = nlmsg_alloc();
    msg_1 = nlmsg_alloc();

    if (!msg_0 || !msg_1) {
      perror("failed to allocate netlink message\n");
      return -1;
    }
    cb_0 = nl_cb_alloc(NL_CB_DEFAULT);
    s_cb_0 = nl_cb_alloc(NL_CB_DEFAULT);
    cb_1 = nl_cb_alloc(NL_CB_DEFAULT);
    s_cb_1 = nl_cb_alloc(NL_CB_DEFAULT);

    if (!cb_1 || !s_cb_1 || !cb_0 || !s_cb_0) {
      perror("failed to allocate netlink callbacks\n");
      nlmsg_free(msg_1);
      nlmsg_free(msg_0);
      nl80211_cleanup(&nlstate_0);
      nl80211_cleanup(&nlstate_1);
      return -1;
    }
    genlmsg_put(msg_0, 0, 0, nlstate_0.nl80211_id, 0,768, 17, 0);
    genlmsg_put(msg_1, 0, 0, nlstate_1.nl80211_id, 0,768, 17, 0);
    NLA_PUT_U32(msg_0, NL80211_ATTR_IFINDEX, devidx_0);
    NLA_PUT_U32(msg_1, NL80211_ATTR_IFINDEX, devidx_1);

    nl_cb_set(cb_0, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
    nl_cb_set(cb_1, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);
    nl_socket_set_cb(nlstate_0.nl_sock, s_cb_0);
    nl_socket_set_cb(nlstate_1.nl_sock, s_cb_1);

    err_0 = nl_send_auto_complete(nlstate_0.nl_sock, msg_0);
    err_1 = nl_send_auto_complete(nlstate_1.nl_sock, msg_1);
    if (err_0 < 0 || err_1 <0 ){
      nl_cb_put(cb_0);
      nl_cb_put(s_cb_0);
      nlmsg_free(msg_0);
      nl_cb_put(cb_1);
      nl_cb_put(s_cb_1);
      nlmsg_free(msg_1);

    nla_put_failure :
      nl80211_cleanup(&nlstate_0); // come back again next iteration ...
      nl80211_cleanup(&nlstate_1); // come back again next iteration ...
      continue ; // right  ? 
    }

    nl_cb_err(cb_0, NL_CB_CUSTOM, error_handler, &err_0);
    nl_cb_set(cb_0, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_0);
    nl_cb_set(cb_0, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err_0);

    nl_cb_err(cb_1, NL_CB_CUSTOM, error_handler, &err_1);
    nl_cb_set(cb_1, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_1);
    nl_cb_set(cb_1, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err_1);

    fd_0=nl_socket_get_fd(nlstate_0.nl_sock);
    fd_1=nl_socket_get_fd(nlstate_1.nl_sock);
 */
      FD_ZERO(&fd_wait);
    FD_SET(fd_0,&fd_wait);
    FD_SET(fd_1,&fd_wait);

      FD_SET(in_fd_0, &fd_wait);
      FD_SET(in_fd_1, &fd_wait);
      st.tv_sec  = 0;
      st.tv_usec = 200;
      retval=select(FD_SETSIZE, &fd_wait, NULL, NULL, &st);
      switch(retval)
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

/*
	      if(FD_ISSET(fd_0,&fd_wait)){
        nl_recvmsgs(nlstate_0.nl_sock, cb_0);
      }
      if(FD_ISSET(fd_1,&fd_wait)){
        nl_recvmsgs(nlstate_1.nl_sock, cb_1);
      }
*/


     }
      // comes here when select times out or when a packet is processed


/*
    nl_cb_put(cb_0);
    nl_cb_put(s_cb_0);
    nlmsg_free(msg_0);
    nl80211_cleanup(&nlstate_0);

    nl_cb_put(cb_1);
    nl_cb_put(s_cb_1);
    nlmsg_free(msg_1);
    nl80211_cleanup(&nlstate_1);
*/
    }
    return 0 ;
}
