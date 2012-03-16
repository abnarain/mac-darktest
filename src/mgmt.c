#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <ctype.h>
#include "td-util.h"
#include "pkts.h"
#include "llc.h"
#include "ieee80211.h"
int fn_print(register const uchar *s, register const uchar *ep, struct rcv_pkt * paket)
{
  register int ret;
  register uchar c;
  char temp[48];
  int i = 0;
  ret = 1;                        /* assume truncated */
  while (ep == NULL || s < ep) {
    c = *s++;
    if (c == '\0') {
      temp[i]=c ;
      ret = 0;
      printf("%c",c);
      break;
    }
    if (!isascii(c)) {
      c = toascii(c);
      temp[i]='-';//c prev
      printf("-");
      continue;
    }
    if (!isprint(c)) {
      c ^= 0x40;      /* DEL to ?, others to alpha */
      temp[i]='^';//c prev
      printf("%c",c);
      continue;
    }
    temp[i]=c;
    printf("%c",c);
    i++;
  }
  if(ret==1)
    temp[i]='\0';
  printf(" ssid is :!!%s!!\n",temp);
  //  memcpy(paket->essid,temp, strlen(temp));
  return ret;
}
int parse_elements(struct mgmt_body_t *pbody, const uchar *p, int offset,u_int length, struct rcv_pkt * paket)
{
  struct ssid_t ssid;
  struct challenge_t challenge;
  struct rates_t rates;
  struct ds_t ds;
  struct cf_t cf;
  struct tim_t tim;

  pbody->challenge_present = 0;
  pbody->ssid_present = 0;
  pbody->rates_present = 0;
  pbody->ds_present = 0;
  pbody->cf_present = 0;
  pbody->tim_present = 0;
  if(paket->pkt_type == MGT_FRAME && paket->p.mgmt_pkt.pkt_subtype== ST_BEACON)
    paket->p.mgmt_pkt.n_enabled=0;

  while (length != 0) {
    if (!TTEST2(*(p + offset), 1))
      return 0;
    if (length < 1)
      return 0;
    switch (*(p + offset)) {
    case E_SSID:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&ssid, p + offset, 2);
      offset += 2;
      length -= 2;
      if (ssid.length != 0) {
        if (ssid.length > sizeof(ssid.ssid) - 1)
          return 0;
        if (!TTEST2(*(p + offset), ssid.length))
          return 0;
        if (length < ssid.length)
          return 0;
        memcpy(&ssid.ssid, p + offset, ssid.length);
        offset += ssid.length;
        length -= ssid.length;
      }
      ssid.ssid[ssid.length] = '\0';
      if (!pbody->ssid_present) {
        pbody->ssid = ssid;
        pbody->ssid_present = 1;
      }
      break;
    case E_CHALLENGE:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&challenge, p + offset, 2);
      offset += 2;
      length -= 2;
      if (challenge.length != 0) {
        if (challenge.length >
            sizeof(challenge.text) - 1)
          return 0;
        if (!TTEST2(*(p + offset), challenge.length))
          return 0;
        if (length < challenge.length)
          return 0;
        memcpy(&challenge.text, p + offset,
               challenge.length);
        offset += challenge.length;
        length -= challenge.length;
      }
      challenge.text[challenge.length] = '\0';
      //
      if (!pbody->challenge_present) {
        pbody->challenge = challenge;
        pbody->challenge_present = 1;
      }
      break;
    case E_RATES:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&rates, p + offset, 2);
      offset += 2;
      length -= 2;
      if (rates.length != 0) {
        if (rates.length > sizeof rates.rate)
          return 0;
        if (!TTEST2(*(p + offset), rates.length))
          return 0;
        if (length < rates.length)
          return 0;
        memcpy(&rates.rate, p + offset, rates.length);
        offset += rates.length;
        length -= rates.length;
      }
      if (!pbody->rates_present && rates.length != 0) {
        pbody->rates = rates;
        pbody->rates_present = 1;
      }
      break;
    case E_DS:
      if (!TTEST2(*(p + offset), 3))
        return 0;
      if (length < 3)
        return 0;
      memcpy(&ds, p + offset, 3);
      offset += 3;
      length -= 3;
      if (!pbody->ds_present) {
        pbody->ds = ds;
        pbody->ds_present = 1;
      }
      break;
    case E_CF:
      if (!TTEST2(*(p + offset), 8))
        return 0;
      if (length < 8)
        return 0;
      memcpy(&cf, p + offset, 8);
      offset += 8;
      length -= 8;
      if (!pbody->cf_present) {
        pbody->cf = cf;
        pbody->cf_present = 1;
      }
      break;
    case E_TIM:
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      memcpy(&tim, p + offset, 2);
      offset += 2;
      length -= 2;
      if (!TTEST2(*(p + offset), 3))
        return 0;
      if (length < 3)
        return 0;
      memcpy(&tim.count, p + offset, 3);
      offset += 3;
      length -= 3;

      if (tim.length <= 3)
        break;
      if (tim.length - 3 > (int)sizeof tim.bitmap)
        return 0;
      if (!TTEST2(*(p + offset), tim.length - 3))
        return 0;
      if (length < (u_int)(tim.length - 3))
        return 0;
      memcpy(tim.bitmap, p + (tim.length - 3),
             (tim.length - 3));
      offset += tim.length - 3;
      length -= tim.length - 3;
      if (!pbody->tim_present) {
        pbody->tim = tim;
        pbody->tim_present = 1;
      }
      break;
    default:
      if (*(p + offset)== HT_CAP){
        if(paket->ath_crc_err == 0 )
	  if(paket->pkt_type == MGT_FRAME && paket->p.mgmt_pkt.pkt_subtype== ST_BEACON){
	    paket->p.mgmt_pkt.n_enabled=1;
	    printf("its HT ! \n");
	  }
      }
      if (!TTEST2(*(p + offset), 2))
        return 0;
      if (length < 2)
        return 0;
      if (!TTEST2(*(p + offset + 2), *(p + offset + 1)))
        return 0;
      if (length < (u_int)(*(p + offset + 1) + 2))
        return 0;
      offset += *(p + offset + 1) + 2;
      length -= *(p + offset + 1) + 2;
      break;
    }
  }

  return 1;
}

int handle_beacon(const uchar *p, u_int length, struct rcv_pkt * paket)
{
  struct mgmt_body_t pbody;
  int offset = 0;
  int ret;
  memset(&pbody, 0, sizeof(pbody));
  if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN + IEEE802_11_CAPINFO_LEN))
    return 0;
  if (length < IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
      IEEE802_11_CAPINFO_LEN)
    return 0;
  memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
  offset += IEEE802_11_TSTAMP_LEN;
  length -= IEEE802_11_TSTAMP_LEN;
  pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_BCNINT_LEN;
  length -= IEEE802_11_BCNINT_LEN;
  pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_CAPINFO_LEN;
  length -= IEEE802_11_CAPINFO_LEN;

  ret = parse_elements(&pbody, p, offset, length,paket);
  if (pbody.ssid_present) {
    fn_print(pbody.ssid.ssid, NULL,paket);
  }
  if (pbody.ds_present) {
    //    paket->channel= ;
    printf("packet channel = %d\n",pbody.ds.channel);
  }
  paket->p.mgmt_pkt.cap_privacy=  CAPABILITY_PRIVACY(pbody.capability_info) ? 1 :0 ;
  printf("%s \n",   CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");

  u_int8_t _r;
  if (pbody.rates_present) {
    _r= pbody.rates.rate[pbody.rates.length -1] ;
    paket->p.mgmt_pkt.rate_max=(float)((.5 * ((_r) & 0x7f)));
    printf("packet rate is %d \n", paket->p.mgmt_pkt.rate_max);
  }
  else {
    paket->p.mgmt_pkt.rate_max=0.0; // undefined rate, because of bad fcs (might be a reason)
  }
  paket->p.mgmt_pkt.cap_ess_ibss =55;
  paket->p.mgmt_pkt.cap_ess_ibss=  CAPABILITY_ESS(pbody.capability_info) ? 1:2;
  return ret;
}


int handle_probe_request(const uchar *p, u_int length,struct rcv_pkt * paket)
{
  struct mgmt_body_t  pbody;
  int offset = 0;
  int ret;
  /*
  memset(&pbody, 0, sizeof(pbody));

  ret = parse_elements(&pbody, p, offset, length,paket);

  if (pbody.ssid_present) {
    fn_print(pbody.ssid.ssid, NULL,paket);
  }else {
    printf("!ssid \n");
  }
  u_int8_t _r;
  if (pbody.rates_present) {
    _r= pbody.rates.rate[pbody.rates.length -1] ;
    //    paket->rate_max=(float)((.5 * ((_r) & 0x7f)));
    printf("packet rate is %d \n",(float)((.5 * ((_r) & 0x7f))));
  }
  else {
    //    paket->rate_max=0.0; // undefined rate, because of bad fcs (might be a reason)
  }
  */
  return ret;
}

int
handle_probe_response(const uchar *p, u_int length,struct rcv_pkt * paket)
{
  struct mgmt_body_t  pbody;
  int offset = 0;
  int ret;

  memset(&pbody, 0, sizeof(pbody));

  if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
	      IEEE802_11_CAPINFO_LEN))
    return 0;
  if (length < IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
      IEEE802_11_CAPINFO_LEN)
    return 0;
  memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
  offset += IEEE802_11_TSTAMP_LEN;
  length -= IEEE802_11_TSTAMP_LEN;
  pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_BCNINT_LEN;
  length -= IEEE802_11_BCNINT_LEN;
  pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_CAPINFO_LEN;
  length -= IEEE802_11_CAPINFO_LEN;

  ret = parse_elements(&pbody, p, offset, length,paket);
  /*
  if (pbody.ssid_present) {
    fn_print(pbody.ssid.ssid, NULL,paket);
  }else {
	printf("!ssid \n");
}
  
  u_int8_t _r;
  if (pbody.rates_present) {
    _r= pbody.rates.rate[pbody.rates.length -1] ;
    paket->rate_max=(float)((.5 * ((_r) & 0x7f)));
    printf("packet rate is %d \n", paket->rate_max);
  }
  else {
    paket->rate_max=0.0; // undefined rate, because of bad fcs (might be a reason)
    printf("! rate \n");
  }

if (pbody.ds_present) {
    paket->channel= pbody.ds.channel;
    printf(" channel = %u\n",paket->channel);
  }else{
    printf("!ds \n");
 }
  */
  return ret;
}

int handle_data( u_int16_t fc, uchar *p,int hdrlen, struct rcv_pkt * paket ){
  if(DATA_FRAME_IS_NULL(FC_SUBTYPE(fc))){
    //       printf("no data\n");
  }
  if (FC_WEP(fc)) {
    //printf("ENC \n");
  }
  if( FC_SUBTYPE(fc)== IEEE80211_STYPE_DATA || FC_SUBTYPE(fc)== 0x8 ){     
    int idx =0;
    p=p+hdrlen +8;
    //       printf("\nnew\n");
    //for (idx=0;idx<40 ;idx++)
    //printf("%02x ",*(p+idx));       
    
    //struct llc_hdr* llc = (struct llc_hdr*)(p + hdrlen); 	        
    //   uchar *payload = ((uchar*)f) +hdrlen;
    //u_int16_t ethertype = (*(payload+6) << 8) | *(payload+7);        
    //       printf("control is %x\n",control);
    struct llc_hdr * llc = (struct llc_hdr *) p;
    u_int16_t llc_type =  ntohs(llc->snap.ether_type);
    //	 printf("dsap=%02x ssap=%02x \n",llc->dsap ,llc->ssap);
    //	 printf("llc type=%02x\n",llc_type);
    
    if (llc_type == ETHERTYPE_ARP) {
      //	   printf("!!!!!!!!!!!! arp!!!!!!!!!!!!!!!! \n");
      
    } else if (llc_type == ETHERTYPE_IP  ) {
      //        if (jh->caplen_ < hdrlen + sizeof(*llc) + sizeof(struct iphdr))
      //        return;
      struct  iphdr* ih = (struct iphdr*)(llc+1);
      if (ih->protocol == IPPROTO_TCP){
	printf("$$$$ tcp $$$$ \n");
      }
      else if (ih->protocol == IPPROTO_UDP){
	//	     printf("udp \n");
      }
      else if (ih->protocol == IPPROTO_ICMP){
	//printf("####icmp## \n");
      }
    }
    
  }
  printf("\n---\n");
  return 1 ; 
}
