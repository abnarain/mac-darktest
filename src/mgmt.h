#ifndef _MGMT_H_
#define _MGMT_H_
#include "pkts.h"
int handle_beacon(const uchar *p, u_int length, struct rcv_pkt * paket);          
int handle_data(const u_int16_t fc, const uchar *p, int hdrlen, struct rcv_pkt *paket);
#endif /*_MGMT_H_ */
