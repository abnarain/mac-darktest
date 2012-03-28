#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <zlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <sys/time.h>
#include <inttypes.h>
#include "ieee80211.h"
#include "td-util.h"
#include "pkts.h"
#include "address_table.h"

#include "anonymization.h"

int sequence_number = 0 ;
char bismark_id[256] ;
int64_t start_timestamp_microseconds;


mgmt_address_table_t mgmt_address_table ; 
data_address_table_t data_address_table ; 
control_address_table_t control_address_table ; 

int initialize_bismark_id() {  
  FILE* handle = fopen(BISMARK_ID_FILENAME, "r");
  if (!handle) {
    perror("Cannot open Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  if(fscanf(handle, "%255s\n", bismark_id) < 1) {
    perror("Cannot read Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  fclose(handle);
  return 0;
}

int write_update(){
  printf("write update\n");
  gzFile handle = gzopen (PENDING_UPDATE_FILENAME, "wb");
  /*
    if (!handle) {
    perror("Could not open update file for writing\n");
    exit(1);
    }
  
    time_t current_timestamp = time(NULL);
    if (!gzprintf(handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing update\n");
    exit(1);
    }
  */
  address_control_table_write_update(&control_address_table,handle);
  address_mgmt_table_write_update(&mgmt_address_table,handle);
  address_data_table_write_update(&data_address_table,handle);
  
  gzclose(handle);
  /*
    gzFile handle_digest = gzopen (PENDING_UPDATE_FILENAME_DIGEST, "wb");
    if (!handle_digest) {
    perror("Could not open update file for writing\n");
    exit(1);
    }
    if (anonymization_write_update(handle_digest)) {
    perror("Could not write anonymization update");
    exit(1);
    }
    
    gzclose(handle_digest);
  */
  ++sequence_number;
  address_control_table_init(&control_address_table);
  address_data_table_init(&data_address_table);
  address_mgmt_table_init(&mgmt_address_table);
  
  //do nothing 
  return 0;
  
}
void address_mgmt_table_init(mgmt_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_data_table_init(data_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_control_table_init(control_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

/*TODO:
  Rssi avg value to be stored 
*/

int address_data_table_lookup(data_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  u_int8_t dest_m_address[sizeof(paket->p.data_pkt.dst)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  //     printf("mac address %s\n", paket->mac_address);
  //     printf("essid %s \n", paket->essid);
  memcpy(dest_m_address,paket->p.data_pkt.dst,sizeof(paket->p.data_pkt.dst));
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].dest_mac_address, dest_m_address, sizeof(dest_m_address)) && 
	  !memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	// TODO : add the antilog of it 
	table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  if( paket->short_preamble_err)
	    table->entries[table->last].short_preamble_count++ ;
	  if(paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  if(paket->more_data)
	    table->entries[table->last].more_data_count++;
	  if(paket->retry)  
	    table->entries[table->last].retry_count ++;
	  if(paket->strictly_ordered)
	    table->entries[table->last].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[table->last].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[table->last].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  
	  table->entries[table->last].freq =paket->freq ; 
	  table->entries[table->last].rate=paket->rate;
	  table->entries[table->last].channel_rcv=paket->channel_rcv;	  
	  table->entries[table->last].antenna = paket->antenna;	  

	  table->entries[table->last].data_count++;
	  if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
	    table->entries[table->last].st_data_count++;
	    if(paket->p.data_pkt.eth_type== ETHERTYPE_ARP)
	      table->entries[table->last].arp_count++ ;
	    else if(paket->p.data_pkt.eth_type== ETHERTYPE_IP){
	      table->entries[table->last].ip_count++;
	      
	      if( paket->p.data_pkt.transport_type==IPPROTO_TCP)
		table->entries[table->last].tcp_count++ ;
	      
	      if(paket->p.data_pkt.transport_type==IPPROTO_UDP)		
		table->entries[table->last].udp_count++;
	      
	      if(paket->p.data_pkt.transport_type==IPPROTO_ICMP)
		table->entries[table->last].icmp_count++ ;
	    }
	  } else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // node data
	    table->entries[table->last].st_no_data_count++ ; 
	}    
	return mac_id;
      }
    }
  }
  
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  //TODO : add info on the data packets src and destination 
  
  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  memcpy(table->entries[table->last].dest_mac_address, paket->p.data_pkt.dst, sizeof(paket->p.data_pkt.dst));
  table->entries[table->last].total_packets=  1;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  
  table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
  }	
  else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    table->entries[table->last].freq =paket->freq ; 
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  
    
    table->entries[table->last].data_count=1;
    if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
      table->entries[table->last].st_data_count=1;
      if(paket->p.data_pkt.eth_type== ETHERTYPE_ARP)
	table->entries[table->last].arp_count=1 ;
      else if(paket->p.data_pkt.eth_type== ETHERTYPE_IP){
	table->entries[table->last].ip_count=1 ;
	if( paket->p.data_pkt.transport_type==IPPROTO_TCP)
	  table->entries[table->last].tcp_count=1 ;	  
	if(paket->p.data_pkt.transport_type==IPPROTO_UDP)		
	  table->entries[table->last].udp_count=1 ;	  
	if(paket->p.data_pkt.transport_type==IPPROTO_ICMP)
	  table->entries[table->last].icmp_count=1 ;
      }
    }else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // node data
      table->entries[table->last].st_no_data_count=1  ;   
  }
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
  
}

int address_control_table_lookup(control_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  //     printf("mac address %s\n", paket->mac_address);
  //     printf("essid %s \n", paket->essid);
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	// TODO : add the antilog of it 
	  table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  if( paket->short_preamble_err)
	    table->entries[table->last].short_preamble_count++ ;
	  
	  if(paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  
	  if(paket->more_data)
	    table->entries[table->last].more_data_count++;
	  
	  if(paket->retry)  
	    table->entries[table->last].retry_count ++;
	  if(paket->strictly_ordered)
	    table->entries[table->last].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[table->last].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[table->last].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  
	  table->entries[table->last].freq =paket->freq ; 
	  table->entries[table->last].rate=paket->rate;
	  table->entries[table->last].channel_rcv=paket->channel_rcv;	  
	  table->entries[table->last].antenna = paket->antenna;	  

      table->entries[table->last].ctrl_count++;

      if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS)
	table->entries[table->last].rts_count++;
      else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS)
	table->entries[table->last].cts_count++;
      else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_ACKNOWLEDGEMENT)
	table->entries[table->last].ack_count++;
	}    
	return mac_id;
      }
    }
  }



  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }

  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets=  table->entries[table->last].total_packets+1;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
  }	
  else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;
        
    table->entries[table->last].freq =paket->freq ; 
    
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  

   table->entries[table->last].ctrl_count++;
    if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS)
      table->entries[table->last].rts_count=1;
    else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS)
      table->entries[table->last].cts_count=1;
    else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_ACKNOWLEDGEMENT)
    table->entries[table->last].ack_count=1;
  }  
  
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
}
int address_mgmt_table_lookup(mgmt_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  //     printf("mac address %s\n", paket->mac_address);
  //     printf("essid %s \n", paket->essid);
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	// TODO : add the antilog of it 
	  table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  if( paket->short_preamble_err)
	    table->entries[table->last].short_preamble_count++ ;
	  
	  if(paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  
	  if(paket->more_data)
	    table->entries[table->last].more_data_count++;
	  
	  if(paket->retry)  
	    table->entries[table->last].retry_count ++;
	  if(paket->strictly_ordered)
	    table->entries[table->last].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[table->last].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[table->last].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[table->last].more_flag_count++;
	  
	  table->entries[table->last].freq =paket->freq ; 
	  table->entries[table->last].rate=paket->rate;
	  table->entries[table->last].channel_rcv=paket->channel_rcv;	  
	  table->entries[table->last].antenna = paket->antenna;	  
	  	  
	  //mgmt related
	  table->entries[table->last].mgmt_count++;
	  if(paket->p.mgmt_pkt.pkt_subtype == ST_BEACON ){	    
	      memcpy(table->entries[table->last].essid, paket->p.mgmt_pkt.essid, sizeof(paket->p.mgmt_pkt.essid));
	      table->entries[table->last].beacon_count++;
	      
	      if(paket->p.mgmt_pkt.n_enabled)
		table->entries[table->last].n_enabled_count++ ;
	      //TODO:   privacy; cap_ess_ibss;  done with the first mgmnt pkt
	      
	      if(paket->p.mgmt_pkt.n_enabled)
		table->entries[table->last].n_enabled_count++; 
	      table->entries[table->last].rate_max= paket->p.mgmt_pkt.rate_max;
	  }
	  else if(paket->p.mgmt_pkt.pkt_subtype== ST_PROBE_RESPONSE)
	    table->entries[table->last].probe_count=1;	  
	}    
	return mac_id;
      }
    }
  }
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  
  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets=  table->entries[table->last].total_packets+1;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  
    table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
  }	
  else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;
        
    table->entries[table->last].freq =paket->freq ; 
    
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    
    table->entries[table->last].antenna = paket->antenna;	  
    
    //mgmt related 
    table->entries[table->last].mgmt_count++;
    if(paket->p.mgmt_pkt.pkt_subtype == ST_BEACON ){
      
      memcpy(table->entries[table->last].essid, paket->p.mgmt_pkt.essid, sizeof(paket->p.mgmt_pkt.essid));
      table->entries[table->last].beacon_count++;
      
      if(paket->p.mgmt_pkt.n_enabled)
	table->entries[table->last].n_enabled_count++ ;
      
      table->entries[table->last].cap_privacy=paket->p.mgmt_pkt.cap_privacy;
      table->entries[table->last].cap_ess_ibss=paket->p.mgmt_pkt.cap_ess_ibss;
      table->entries[table->last].mgmt_channel=paket->p.mgmt_pkt.channel;
      table->entries[table->last].rate_max= paket->p.mgmt_pkt.rate_max;
      
    }
    else if(paket->p.mgmt_pkt.pkt_subtype== ST_PROBE_RESPONSE)
      table->entries[table->last].probe_count=1;
    
  }
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
}


int address_data_table_write_update(data_address_table_t* table,gzFile handle) {
  printf("writing the update in the file \n");
  int idx;
   printf("----------------DATA PACKETS------- \n"); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {

    int mac_id = NORM(table->last - idx + 1);
    u_int8_t *a=table->entries[mac_id].mac_address;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|data_count|anten|freq|ath_crc|ath_phy|rate|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%2.1f\n",
	   table->entries[mac_id].total_packets,
	   table->entries[table->last].data_count,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count,
	   table->entries[mac_id].rate
	   );
    printf("data_|st_data|arp|ip|tcp|udp|icmp|st_no_data_|rssi|rssi\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%2.1f\n",
	   table->entries[table->last].data_count,
	   table->entries[mac_id].st_no_data_count,
	   table->entries[mac_id].st_data_count,
	   table->entries[mac_id].arp_count,
	   table->entries[mac_id].ip_count,
	   table->entries[mac_id].tcp_count,
	   table->entries[mac_id].udp_count,
	   table->entries[mac_id].icmp_count,
	   table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets)
	   );

    /*retransmits 
      if(!gzprintf(handle,"", )){
      perror("error writing the zip file ");
      exit(1);
      }    
      if(!gzprintf(handle,"",)){
      perror("error writing the zip file");
      exit(1);
      }
    */
  }
  return 1; 
}



int address_control_table_write_update(control_address_table_t* table,gzFile handle) {
  printf("writing the update in the file \n");
  int idx;
   printf("----------------CONTROL PACKETS------- \n"); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {

    int mac_id = NORM(table->last - idx + 1);
    u_int8_t *a=table->entries[mac_id].mac_address;
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|ctrl_c|anten|freq|ath_crc|ath_phy|rate|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%2.1f\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].ctrl_count,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count,
	   table->entries[mac_id].rate
	   );
    printf("ctrl_|cts|rts|ack|rssi|rssi\n");
    printf("%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table->entries[mac_id].ctrl_count,
	   table->entries[mac_id].cts_count,
	   table->entries[mac_id].rts_count,
	   table->entries[mac_id].ack_count,
	   table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets)
	   );

    /*retransmits 
      if(!gzprintf(handle,"", )){
      perror("error writing the zip file ");
      exit(1);
      }    
      if(!gzprintf(handle,"",)){
      perror("error writing the zip file");
      exit(1);
      }
    */
  }
  return 1; 
}



int address_mgmt_table_write_update(mgmt_address_table_t* table,gzFile handle) {
  printf("writing the update in the file \n");
  int idx;
   printf("----------------MGMT PACKETS------- \n"); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {

    int mac_id = NORM(table->last - idx + 1);
    u_int8_t *a=table->entries[mac_id].mac_address;
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|mgmt_c|anten|freq|ath_crc|ath_phy|rate|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%2.1f\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].mgmt_count,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count,
	   table->entries[mac_id].rate
	   );  
    printf("essid|mgmt_|beacon_|probe|privacy|ibss|rate_max|rssi|");
    printf("%s|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table->entries[mac_id].essid,
	   table->entries[mac_id].mgmt_count,
	   table->entries[mac_id].beacon_count,
	   table->entries[mac_id].probe_count,
	   table->entries[mac_id].cap_privacy,
	   table->entries[mac_id].cap_ess_ibss,
	   table->entries[mac_id].rate_max,
	   table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets)
	   );

    /*retransmits rssi 
      if(!gzprintf(handle,"", )){
      perror("error writing the zip file ");
      exit(1);
      }    
      if(!gzprintf(handle,"",)){
      perror("error writing the zip file");
      exit(1);
      }
    */
  }
  return 1; 
}
