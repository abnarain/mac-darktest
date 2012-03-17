int write_update(){
	printf("write update\n");
	//do nothing 
};
void address_table_init(address_table_t* table) {
	memset(table, '\0', sizeof(*table));
}
#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

/*TODO:
Rssi avg value to be stored 
Rate value to be dug out from kernel and logged 
*/

int address_table_lookup(address_table_t*  table,struct r_packet* paket) {
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
      if (!memcmp(table->entries[mac_id].mac_add, m_address, sizeof(m_address))){
	table->entries[mac_id].packet_count++;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;
	}else if(paket->ath_phy_err){
	  table->entries[mac_id].ath_phy_err_count++;
	}else{
	  if( paket->short_preamble_err)
	    table->entries[table->last].short_preamble_err_count++ ;

	  if(paket->frag_err)
	    table->entries[table->last].frag_err_count++;
	    if(paket->retry)  
	      table->entries[table->last].retry_err_count ++;
	    if(paket->strictly_ordered)
	      table->entries[table->last].strictly_ordered_err_count++;
	    if(paket->pwr_mgmt)
	      table->entries[table->last].pwr_mgmt_count++ ;
	    if(paket->wep_enc)
	      table->entries[table->last].wep_enc_count++;
	    if( paket->more_flag)
	      table->entries[table->last].more_flag_count++;
	    
	    table->entries[table->last].freq =paket->freq ; 
	    table->entries[table->last].channel= paket->channel;
	    table->entries[table->last].antenna = paket->antenna;	  
	    
	    if(paket->pkt_type==MGT_FRAME){
	      table->entries[table->last].mgmt_count++;
	      if(paket->sub_type == ST_BEACON ){
		
		memcpy(table->entries[table->last].essid, paket->essid, sizeof(paket->essid));
		table->entries[table->last].beacon_count++;
		
		if(paket->p.mgmt_pkt.n_enabled)
		  table->entries[table->last].n_enabled_count++ ;
		
		if(paket->p.mgmt_pkt.cap_privacy)
		  table->entries[table->last].cap_privacy; 
		
		if(paket->p.mgmt_pkt.cap_ess_ibss)
		  table->entries[table->last].cap_ess_ibss; 
		
		if(paket->p.mgmt_pkt.n_enabled)
		  table->entries[table->last].n_enabled_count++ 
		    table->entries[table->last].rate_max= paket->p.mgmt.rate_max;
	      }
	      else if(paket->sub_type== ST_PROBE_RESPONSE)
		table->entries[table->last].probe_count=1;
	      
	    }else if( paket->pkt_type==CONTROL_FRAME){
	      if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS)
		table->entries[table->last].rts_count=1;
	      else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS)
		table->entries[table->last].cts_count=1;
	      else if(paket->p.ctrl.pkt.pkt_subtype==CTRL_ACKNOWLEDGEMENT)
		table->entries[table->last].ack_count=1;
	    }else if(paket->pkt_type==DATA_FRAME){
	      if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
		table->entries[table->last].data_count=1;
		if(paket->p.data_type.eth_type== ETHERTYPE_ARP)
		  table->entries[table->last].arp_count=1 ;
		else if(paket->p.data_type.eth_type== ETHERTYPE_IP){
		  table->entries[table->last].ip_count =1;
		  
		  if( paket->p.data_type.transport_type==IPPROTO_TCP)
		    table->entries[table->last].tcp_count=1 ;
		  
		  if(paket->p.data_type.transport_type==IPPROTO_UDP)		
		    table->entries[table->last].udp_count =1;
		  
		  if(paket->p.data_type.transport_type==IPPROTO_ICMP)
		    table->entries[table->last].icmp_count=1 ;
		}
	      } else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // node data
		table->entries[table->last].no_data=1 ; 
	    }	 // otherwise its frame type which we can't decipher as there are 
	    
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
  
  memcpy(table->entries[table->last].mac_add, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets=  table->entries[table->last].total_packets+1;
  
  if(paket->ath_phy_err){
    table->entries[table->last].ath_phy_err_count++;    
	}
  else if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
  }	
  else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_err_count++;
    if(paket->frag_err);
    table->entries[table->last].frag_err_count++;
    if(paket->retry )
      table->entries[table->last].retry_err_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_err_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
    table->entries[table->last].wep_enc_count++;
    if( paket->more_flag)
    table->entries[table->last].more_flag_count++;

    
    table->entries[table->last].freq =paket->freq ; 
    table->entries[table->last].channel= paket->channel;
    table->entries[table->last].antenna = paket->antenna;	  
    
    if(paket->pkt_type==MGT_FRAME){
      table->entries[table->last].mgmt_count++;
      if(paket->sub_type == ST_BEACON ){
	    
	memcpy(table->entries[table->last].essid, paket->essid, sizeof(paket->essid));
	table->entries[table->last].beacon_count++;
	
	if(paket->p.mgmt_pkt.n_enabled)
	  table->entries[table->last].n_enabled_count++ ;
	
	if(paket->p.mgmt_pkt.cap_privacy)
	      table->entries[table->last].cap_privacy; 
	
	if(paket->p.mgmt_pkt.cap_ess_ibss)
	  table->entries[table->last].cap_ess_ibss; 
	
	if(paket->p.mgmt_pkt.n_enabled)
	  table->entries[table->last].n_enabled_count++ 
	    table->entries[table->last].rate_max= paket->p.mgmt.rate_max;
      }
      else if(paket->sub_type== ST_PROBE_RESPONSE)
	table->entries[table->last].probe_count++;		
    }else if( paket->pkt_type==CONTROL_FRAME){
      if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS)
	table->entries[table->last].rts_count++;
      else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS)
	    table->entries[table->last].cts_count++;
      else if(paket->p.ctrl.pkt.pkt_subtype==CTRL_ACKNOWLEDGEMENT)
	table->entries[table->last].ack_count++;
    }else if(paket->pkt_type==DATA_FRAME){
      if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
	table->entries[table->last].data_count++;
	if(paket->p.data_type.eth_type== ETHERTYPE_ARP)
	  table->entries[table->last].arp_count ;
	else if(paket->p.data_type.eth_type== ETHERTYPE_IP){
	  table->entries[table->last].ip_count ;
	  
	  if( paket->p.data_type.transport_type==IPPROTO_TCP)
	    table->entries[table->last].tcp_count ;
	  
	  if(paket->p.data_type.transport_type==IPPROTO_UDP)		
	    table->entries[table->last].udp_count ;

	if(paket->p.data_type.transport_type==IPPROTO_ICMP)
	  table->entries[table->last].icmp_count ;
	}
      } else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // node data
	    table->entries[table->last].no_data  ;
	  
    }	 // otherwise its frame type which we can't decipher as there are 

  }
	
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }
  
  return table->last;
}


int address_table_write_update(address_table_t* table,gzFile handle) {
  printf("writing the update in the file \n");
  int idx;
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
    /*
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
