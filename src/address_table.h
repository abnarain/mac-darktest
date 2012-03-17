#ifndef _ADDRESS_TABLE_T
#define _ADDRESS_TABLE_T

#define MAC_TABLE_ENTRIES 255
typedef struct {

 u_int8_t mac_address[6];
  int64_t time;
  u_int32_t total_packets ;
  // jigdump header 
  u_int8_t rssi;
  u_int16_t freq ;
  u_int8_t antenna;
  u_int32_t ath_crc_err_count;
  u_int32_t ath_phy_err_count;

  u_int32_t short_preamble_err_count;
  u_int32_t phy_wep_err_count;
  u_int32_t retry_count;
  u_int32_t cfp_err_count ;
  u_int32_t more_frag_count ;
  u_int32_t retry_err_count;
  u_int32_t strictly_ordered_err_count;

  u_int8_t cap_privacy ;
  u_int8_t cap_ess_ibss ;
  u_int8_t n_enabled;
  char essid[32];
  u_int8_t channel;
  u_int32_t mgmt_count;

  u_int32_t beacon_count ;
  u_int32_t n_enabled_count ;
  u_int32_t probe_count ;  

  u_int32_t ctrl_count; 
  u_int32_t cts_count ;
  u_int32_t rts_count ;
  u_int32_t ack_count ;

  u_int32_t data_count;
  u_int32_t no_data_count;
  u_int32_t arp_count;
  u_int32_t ip_count;
  u_int32_t tcp_count ;
  u_int32_t udp_count ;
  u_int32_t icmp_count ; 

  u_int32_t retransmits ;
  float rate_max;

  // I have to fix these to get the values 
  char channel_info[5];
  float rate;
  float rate_mcs ;

  u_int32_t pwr_mgmt_count;
  u_int32_t wep_enc_count;
  
  u_int8_t channel;
  u_int8_t antenna; 
  
  u_int16_t freq;
  float rate;
  float rate_mcs ;
  float rate_max; 

} address_table_entry_t;


typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} address_table_t;

address_table_t address_table;

void address_table_init(address_table_t* table);
int address_table_lookup(address_table_t*  table,struct rcv_pkt * paket) ;
int address_table_write_update(address_table_t* table,gzFile handle) ;

#endif
