#ifndef _ADDRESS_TABLE_T
#define _ADDRESS_TABLE_T

#define MAC_TABLE_ENTRIES 2048

#define BISMARK_ID_FILENAME "/etc/bismark/ID"

#define UPDATE_FILENAME_DIGEST "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-digest-%d.gz"
#define PENDING_UPDATE_FILENAME_DIGEST "/tmp/wifi-beacons/current-digest-update.gz"


#define UPDATE_MGMT_FILENAME "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-m-%d.gz"
#define UPDATE_CONTROL_FILENAME "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-c-%d.gz"
#define UPDATE_DATA_FILENAME "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-d-%d.gz"
#define UPDATE_NONE_FILENAME "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-n-%d.gz"

#define PENDING_UPDATE_MGMT_FILENAME "/tmp/wifi-beacons/current-mgmt-update.gz"
#define PENDING_UPDATE_CONTROL_FILENAME "/tmp/wifi-beacons/current-control-update.gz"
#define PENDING_UPDATE_DATA_FILENAME "/tmp/wifi-beacons/current-data-update.gz"
#define PENDING_UPDATE_NONE_FILENAME "/tmp/wifi-beacons/current-none-update.gz"

extern int64_t start_timestamp_microseconds;
extern char bismark_id[256];

typedef struct {

  u_int8_t mac_address[6];
  int64_t time;
  u_int32_t total_packets ;
  // jigdump header 
  float rssi_sum;
  float rssi_lin_sum;
  float rate;
  u_int16_t freq ;
  u_int8_t antenna;
  u_int32_t ath_crc_err_count;
  u_int32_t ath_phy_err_count;
  u_int32_t short_preamble_count;
  u_int8_t channel_rcv;

  u_int32_t phy_wep_count;
  u_int32_t pwr_mgmt_count;
  u_int32_t retry_count;
  u_int32_t more_data_count ;
  u_int32_t more_flag_count ;
  u_int32_t strictly_ordered_count;

  char essid[32];
  u_int8_t channel;
  
  float rate_max;
  u_int32_t beacon_count ;
  u_int32_t n_enabled_count ;
  u_int8_t cap_privacy ;
  u_int8_t mgmt_channel;
  u_int8_t cap_ess_ibss ;
  u_int32_t probe_count ;  

} mgmt_address_table_entry_t;



typedef struct {

 u_int8_t mac_address[6];
  int64_t time;
  u_int32_t total_packets ;
  // jigdump header 
  float rssi_sum;
  float rssi_lin_sum;
  float rate;
  u_int16_t freq ;
  u_int8_t antenna;
  u_int32_t ath_crc_err_count;
  u_int32_t ath_phy_err_count;
  u_int32_t short_preamble_count;
  u_int8_t channel_rcv;

  u_int32_t phy_wep_count;
  u_int32_t pwr_mgmt_count;
  u_int32_t retry_count;
  u_int32_t more_data_count ;
  u_int32_t more_flag_count ;
  u_int32_t strictly_ordered_count;

  u_int32_t cts_count ;
  u_int32_t rts_count ;
  u_int32_t ack_count ;
} control_address_table_entry_t;

typedef struct {

 u_int8_t mac_address[6];
 u_int8_t dest_mac_address[6];
  int64_t time;
  u_int32_t total_packets ;
  // jigdump header 
  float rssi_sum;
  float rssi_lin_sum;
  float rate;
  float rate_mcs_idx ;
  u_int16_t freq ;
  u_int8_t antenna;
  u_int32_t ath_crc_err_count;
  u_int32_t ath_phy_err_count;
  u_int32_t short_preamble_count;
  u_int8_t channel_rcv;

  u_int32_t phy_wep_count;
  u_int32_t pwr_mgmt_count;
  u_int32_t retry_count;
  u_int32_t more_data_count ;
  u_int32_t more_flag_count ;
  u_int32_t strictly_ordered_count;

  u_int32_t st_data_count;
  u_int32_t arp_count;
  u_int32_t ip_count;
  u_int32_t tcp_count ;
  u_int32_t udp_count ;
  u_int32_t icmp_count ; 
  u_int32_t st_no_data_count;
  u_int32_t retransmits ;
  
} data_address_table_entry_t;

typedef struct {

  u_int8_t mac_address[6];
  int64_t time;
  u_int32_t total_packets ;
  // jigdump header 
  float rssi_sum;
  float rssi_lin_sum;
  float rate;
  float rate_mcs_idx ;
  u_int16_t freq ;
  u_int8_t antenna;
  u_int32_t ath_crc_err_count;
  u_int32_t ath_phy_err_count;
  u_int32_t short_preamble_count;
  u_int8_t channel_rcv;

  u_int32_t phy_wep_count;
  u_int32_t pwr_mgmt_count;
  u_int32_t retry_count;
  u_int32_t more_data_count ;
  u_int32_t more_flag_count ;
  u_int32_t strictly_ordered_count;

} none_address_table_entry_t;

typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  none_address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} none_address_table_t;


typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  data_address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} data_address_table_t;



typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  mgmt_address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} mgmt_address_table_t;

typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  control_address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} control_address_table_t;


extern mgmt_address_table_t mgmt_address_table;
void address_mgmt_table_init(mgmt_address_table_t* table);
int address_mgmt_table_lookup(mgmt_address_table_t*  table, struct rcv_pkt * paket) ;
int address_mgmt_table_write_update(mgmt_address_table_t* table, gzFile handle) ;

extern data_address_table_t data_address_table;
void address_data_table_init(data_address_table_t* table);
int address_data_table_lookup(data_address_table_t*  table, struct rcv_pkt * paket) ;
int address_data_table_write_update(data_address_table_t* table, gzFile handle) ;

extern control_address_table_t control_address_table;
void address_control_table_init(control_address_table_t* table);
int address_control_table_lookup(control_address_table_t*  table, struct rcv_pkt * paket) ;
int address_control_table_write_update(control_address_table_t* table, gzFile handle) ;
/*
extern none_address_table_t none_address_table;
void address_none_table_init(none_address_table_t* table);
int address_none_table_lookup(none_address_table_t*  table, struct rcv_pkt * paket) ;
int address_none_table_write_update(none_address_table_t* table, gzFile handle) ;
*/
int initialize_bismark_id() ;
int write_update();





#endif
