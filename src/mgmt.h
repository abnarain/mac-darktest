#include "pkts.h"
int handle_beacon(const uchar *p, u_int length, struct rcv_pkt * paket);          
int handle_probe_request(const uchar *p, u_int length,struct rcv_pkt *paket);
int handle_probe_response(const uchar *p, u_int length,struct rcv_pkt * paket);
int handle_data(const u_int16_t fc, const uchar *p, int hdrlen, struct rcv_pkt *paket);
