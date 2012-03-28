#ifndef _TD_UTILS_H_
#define _TD_UTILS_H_
#ifdef _ALLBSD_SOURCE
#include <machine/endian.h>
#elif __linux__
#include <endian.h>
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#include <byteswap.h>
#endif

#define IEEE802_11_TSTAMP_LEN           8
#define IEEE802_11_BCNINT_LEN           2
#define IEEE802_11_CAPINFO_LEN          2
#define IEEE802_11_LISTENINT_LEN        2
#define IEEE802_11_AP_LEN               6
#define HASHNAMESIZE 1024 
//4096
#define BUFSIZE 128

#define HT_CAP 45
#define HT_INFO  61
#define RSN_INFO  48
#define VENDOR_SPECIFIC 221


#define E_SSID          0
#define E_RATES         1
#define E_FH            2
#define E_DS            3
#define E_CF            4
#define E_TIM           5
#define E_IBSS          6
#define E_CHALLENGE     16


#define IEEE802_11_FC_LEN               2
#define IEEE802_11_DUR_LEN              2
#define IEEE802_11_DA_LEN               6
#define IEEE802_11_SA_LEN               6
#define IEEE802_11_BSSID_LEN            6
#define IEEE802_11_RA_LEN               6
#define IEEE802_11_TA_LEN               6
#define IEEE802_11_SEQ_LEN              2
#define IEEE802_11_CTL_LEN              2
#define IEEE802_11_IV_LEN               3
#define IEEE802_11_KID_LEN              1


extern unsigned char *snapend;
/* Lengths of beacon components. */
#define MGMT_HDRLEN     (IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
                         IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+\
                         IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)


#define TTEST2(var, l) (snapend - (l) <= snapend && \
			(const u_char *)&(var) <= snapend - (l))


#define CAPABILITY_ESS(cap)     ((cap) & 0x0001)
#define CAPABILITY_IBSS(cap)    ((cap) & 0x0002)
#define CAPABILITY_CFP(cap)     ((cap) & 0x0004)
#define CAPABILITY_CFP_REQ(cap) ((cap) & 0x0008)
#define CAPABILITY_PRIVACY(cap) ((cap) & 0x0010)

#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)        ((fc) & 0x0400)
#define FC_RETRY(fc)            ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)       ((fc) & 0x1000)
#define FC_MORE_DATA(fc)        ((fc) & 0x2000)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_ORDER(fc)            ((fc) & 0x8000)
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)


#define IEEE80211_CHAN_FHSS \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define IEEE80211_CHAN_A \
        (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_PUREG \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define IS_CHAN_FHSS(flags) \
        ((flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define IS_CHAN_A(flags) \
        ((flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define IS_CHAN_B(flags) \
        ((flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define IS_CHAN_PUREG(flags) \
        ((flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define IS_CHAN_G(flags) \
        ((flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define IS_CHAN_ANYG(flags) \
        (IS_CHAN_PUREG(flags) || IS_CHAN_G(flags))


#ifdef LBL_ALIGN

#ifdef HAVE___ATTRIBUTE__
typedef struct {
        u_int16_t       val;
} __attribute__((packed)) unaligned_u_int16_t;

typedef struct {
        u_int32_t       val;
} __attribute__((packed)) unaligned_u_int32_t;

#define EXTRACT_16BITS(p) \
        ((u_int16_t)ntohs(((const unaligned_u_int16_t *)(p))->val))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(((const unaligned_u_int32_t *)(p))->val))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)(((u_int64_t)ntohl(((const unaligned_u_int32_t *)(p) + 0)->val)) << 32 | \
                     ((u_int64_t)ntohl(((const unaligned_u_int32_t *)(p) + 1)->val)) << 0))

#else /* HAVE___ATTRIBUTE__ */
/*
 * We don't have __attribute__, so do unaligned loads of big-endian
 * quantities the hard way - fetch the bytes one at a time and
 * assemble them.
 */
#define EXTRACT_16BITS(p) \
        ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 0) << 8 | \
                     (u_int16_t)*((const u_int8_t *)(p) + 1)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 24 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 3)))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 0) << 56 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 1) << 48 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 2) << 40 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 3) << 32 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 4) << 24 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 5) << 16 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 6) << 8 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 7)))
#endif /* HAVE___ATTRIBUTE__ */
#else /* LBL_ALIGN */
/*
 * The processor natively handles unaligned loads, so we can just
 * cast the pointer and fetch through it.
 */
#define EXTRACT_16BITS(p) \
        ((u_int16_t)ntohs(*(const u_int16_t *)(p)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(*(const u_int32_t *)(p)))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)(((u_int64_t)ntohl(*((const u_int32_t *)(p) + 0))) << 32 | \
                     ((u_int64_t)ntohl(*((const u_int32_t *)(p) + 1))) << 0))
#endif // LBL_ALIGN 

#define EXTRACT_24BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2)))

/*
 * Macros to extract possibly-unaligned little-endian integral values.
 * XXX - do loads on little-endian machines that support unaligned loads?
 */
#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
        ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int16_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_32BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_24BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_64BITS(p) \
        ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 0)))



#ifndef roundup2
#define roundup2(x, y)  (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

static const int ieee80211_htrates[16] = {
  13,             /* IFM_IEEE80211_MCS0 */
  26,             /* IFM_IEEE80211_MCS1 */
  39,             /* IFM_IEEE80211_MCS2 */
  52,             /* IFM_IEEE80211_MCS3 */
  78,             /* IFM_IEEE80211_MCS4 */
  104,            /* IFM_IEEE80211_MCS5 */
  117,            /* IFM_IEEE80211_MCS6 */
  130,            /* IFM_IEEE80211_MCS7 */
  26,             /* IFM_IEEE80211_MCS8 */
  52,             /* IFM_IEEE80211_MCS9 */
  78,             /* IFM_IEEE80211_MCS10 */
  104,            /* IFM_IEEE80211_MCS11 */
  156,            /* IFM_IEEE80211_MCS12 */
  208,            /* IFM_IEEE80211_MCS13 */
  234,            /* IFM_IEEE80211_MCS14 */
  260,            /* IFM_IEEE80211_MCS15 */
};

#define EXTRACT_LE_16BITS(p) \
  ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
	       (u_int16_t)*((const u_int8_t *)(p) + 0)))

#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define FC_ORDER(fc)            ((fc) & 0x8000)


#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)

#define FCF_FLAGS(x)           (((x) & 0xFF00) >> 8)

#define MGT_FRAME            0x00  /* Frame type is management */
#define CONTROL_FRAME        0x01  /* Frame type is control */
#define DATA_FRAME           0x02  /* Frame type is Data */


#define MGT_ASSOC_REQ          0x00  /* association request        */
#define MGT_ASSOC_RESP         0x01  /* association response       */
#define MGT_REASSOC_REQ        0x02  /* reassociation request      */
#define MGT_REASSOC_RESP       0x03  /* reassociation response     */
#define MGT_PROBE_REQ          0x04  /* Probe request              */
#define MGT_PROBE_RESP         0x05  /* Probe response             */
#define MGT_MEASUREMENT_PILOT  0x06  /* Measurement Pilot          */
#define MGT_BEACON             0x08  /* Beacon frame               */
#define MGT_ATIM               0x09  /* ATIM                       */
#define MGT_DISASS             0x0A  /* Disassociation             */
#define MGT_AUTHENTICATION     0x0B  /* Authentication             */
#define MGT_DEAUTHENTICATION   0x0C  /* Deauthentication           */
#define MGT_ACTION             0x0D  /* Action                     */
#define MGT_ACTION_NO_ACK      0x0E  /* Action No Ack              */
#define MGT_ARUBA_WLAN         0x0F  /* Aruba WLAN Specific        */

//#define CTRL_CONTROL_WRAPPER 0x17  /* Control Wrapper        */
#define CTRL_BLOCK_ACK_REQ   0x18  /* Block ack Request        */
#define CTRL_BLOCK_ACK       0x19  /* Block ack          */
//#define CTRL_PS_POLL         0x1A  /* power-save poll               */
//#define CTRL_RTS             0x1B  /* changed by abhinav request to send */
//#define CTRL_CTS             0x1C  /* clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 0x1D  /* acknowledgement               */
#define CTRL_CFP_END         0x1E  /* contention-free period end    */
#define CTRL_CFP_ENDACK      0x1F  /* contention-free period end/ack */

#define DATA                        0x20  /* Data                       */
#define DATA_CF_ACK                 0x21  /* Data + CF-Ack              */
#define DATA_CF_POLL                0x22  /* Data + CF-Poll             */
#define DATA_CF_ACK_POLL            0x23  /* Data + CF-Ack + CF-Poll    */
#define DATA_NULL_FUNCTION          0x24  /* Null function (no data)    */
#define DATA_CF_ACK_NOD             0x25  /* CF-Ack (no data)           */
#define DATA_CF_POLL_NOD            0x26  /* CF-Poll (No data)          */
#define DATA_CF_ACK_POLL_NOD        0x27  /* CF-Ack + CF-Poll (no data) */

#define DATA_QOS_DATA               0x28  /* QoS Data                   */
#define DATA_QOS_DATA_CF_ACK        0x29  /* QoS Data + CF-Ack        */
#define DATA_QOS_DATA_CF_POLL       0x2A  /* QoS Data + CF-Poll      */
#define DATA_QOS_DATA_CF_ACK_POLL   0x2B  /* QoS Data + CF-Ack + CF-Poll    */
#define DATA_QOS_NULL               0x2C  /* QoS Null        */
#define DATA_QOS_CF_POLL_NOD        0x2E  /* QoS CF-Poll (No Data)      */
#define DATA_QOS_CF_ACK_POLL_NOD    0x2F  /* QoS CF-Ack + CF-Poll (No Data) */

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24  /* Length of Managment frame-headers */

#define FLAG_ORDER            0x80

#define DATA_FRAME_IS_NULL(x)  ((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)     ((x) & 0x08)
#define IS_STRICTLY_ORDERED(x) ((x) & FLAG_ORDER)



#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         (FLAG_FROM_DS << 8)
#define DATA_ADDR_T3         (FLAG_TO_DS << 8)
#define DATA_ADDR_T4         ((FLAG_TO_DS|FLAG_FROM_DS) << 8)

#define ST_ASSOC_REQUEST        0x0
#define ST_ASSOC_RESPONSE       0x1
#define ST_REASSOC_REQUEST      0x2
#define ST_REASSOC_RESPONSE     0x3
#define ST_PROBE_REQUEST        0x4
#define ST_PROBE_RESPONSE       0x5
/* RESERVED                     0x6  */
/* RESERVED                     0x7  */
#define ST_BEACON               0x8
#define ST_ATIM                 0x9
#define ST_DISASSOC             0xA
#define ST_AUTH                 0xB
#define ST_DEAUTH               0xC
#define ST_ACTION               0xD
/* RESERVED                     0xE  */
/* RESERVED                     0xF  */


#define CTRL_CONTROL_WRAPPER    0x7
#define CTRL_BAR        0x8
#define CTRL_BA         0x9
#define CTRL_PS_POLL    0xA
#define CTRL_RTS        0xB
#define CTRL_CTS        0xC
#define CTRL_ACK        0xD
#define CTRL_CF_END     0xE
#define CTRL_END_ACK    0xF

#define DATA_DATA                       0x0
#define DATA_DATA_CF_ACK                0x1
#define DATA_DATA_CF_POLL               0x2
#define DATA_DATA_CF_ACK_POLL           0x3
#define DATA_QOS_NODATA                 0xC
#define DATA_QOS_CF_POLL_NODATA         0xE
#define DATA_QOS_CF_ACK_POLL_NODATA     0xF
typedef unsigned char      uchar;



#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#define IEEE80211_CHAN_DYN      0x0400  /* Dynamic CCK-OFDM channel */
#define IEEE80211_CHAN_GFSK     0x0800  /* GFSK channel (FHSS PHY) */

#define IEEE80211_CHAN_STURBO   0x02000 /* 11a static turbo channel only */
#define IEEE80211_CHAN_HALF     0x04000 /* Half rate channel */
#define IEEE80211_CHAN_QUARTER  0x08000 /* Quarter rate channel */
#define IEEE80211_CHAN_HT20     0x10000 /* HT 20 channel */
#define IEEE80211_CHAN_HT40U    0x20000 /* HT 40 channel w/ ext above */
#define IEEE80211_CHAN_HT40D    0x40000 /* HT 40 channel w/ ext below */

#endif


