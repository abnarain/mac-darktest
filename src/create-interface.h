#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>

int checkup(char* device) ;
int open_infd(const char device[]);
int down_radio_interface(const char device[]);
int up_radio_interface(const char device[]);
int config_radio_interface(const char device[]);
u_int64_t timeval_to_int64(const struct  timeval *tv);
int k_pkt_stats(int in_fd);
