/* packet-dlep.h
 * Definitions for DLEP packet disassembly structures and routines
 *
 * See: https://www.rfc-editor.org/rfc/rfc8175.txt
 *
 * Copyright (C) 2019 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* Section 13: DLEP Data Items */

/* DLEP Data Item Lengths (bytes) */
#define DLEP_DIT_STATUS_MINLEN      1     /* variable length */
#define DLEP_DIT_V4CONN_LEN         5
#define DLEP_DIT_V4CONN_WPORT_LEN   7
#define DLEP_DIT_V6CONN_LEN         17
#define DLEP_DIT_V6CONN_WPORT_LEN   19
#define DLEP_DIT_PEERTYPE_MINLEN    1     /* variable length */
#define DLEP_DIT_HEARTBEAT_LEN      4
/* EXTSUPP has variable, non-negative length */
#define DLEP_DIT_MACADDR_EUI48_LEN  6
#define DLEP_DIT_MACADDR_EUI64_LEN  8
#define DLEP_DIT_V4ADDR_LEN         5
#define DLEP_DIT_V6ADDR_LEN         17
#define DLEP_DIT_V4SUBNET_LEN       6
#define DLEP_DIT_V6SUBNET_LEN       18
#define DLEP_DIT_MDRR_LEN           8
#define DLEP_DIT_MDRT_LEN           8
#define DLEP_DIT_CDRR_LEN           8
#define DLEP_DIT_CDRT_LEN           8
#define DLEP_DIT_LAT_LEN            8
#define DLEP_DIT_RES_LEN            1
#define DLEP_DIT_RLQR_LEN           1
#define DLEP_DIT_RLQT_LEN           1
#define DLEP_DIT_MTU_LEN            2

/* DLEP Data Item Flags Lengths (bytes) */
#define DLEP_DIT_V4CONN_FLAGS_LEN   1
#define DLEP_DIT_V6CONN_FLAGS_LEN   1
#define DLEP_DIT_V4ADDR_FLAGS_LEN   1
#define DLEP_DIT_V6ADDR_FLAGS_LEN   1
#define DLEP_DIT_PEERTYPE_FLAGS_LEN 1
#define DLEP_DIT_V4SUBNET_FLAGS_LEN 1
#define DLEP_DIT_V6SUBNET_FLAGS_LEN 1


/* Section 15: IANA Considerations */

/* Section 15.2: DLEP Signal Type Codes */
#define DLEP_SIG_RESERVED         0
#define DLEP_SIG_PEERDISC         1
#define DLEP_SIG_PEEROFFR         2

/* Section 15.3: DLEP Message Type Codes */
#define DLEP_MSG_RESERVED         0
#define DLEP_MSG_SESSINIT         1
#define DLEP_MSG_SESSINITRESP     2
#define DLEP_MSG_SESSUPDATE       3
#define DLEP_MSG_SESSUPDATERESP   4
#define DLEP_MSG_SESSTERM         5
#define DLEP_MSG_SESSTERMRESP     6
#define DLEP_MSG_DESTUP           7
#define DLEP_MSG_DESTUPRESP       8
#define DLEP_MSG_DESTANN          9
#define DLEP_MSG_DESTANNRESP      10
#define DLEP_MSG_DESTDOWN         11
#define DLEP_MSG_DESTDOWNRESP     12
#define DLEP_MSG_DESTUPDATE       13
#define DLEP_MSG_LINKCHARRQST     14
#define DLEP_MSG_LINKCHARRESP     15
#define DLEP_MSG_HEARTBEAT        16

/* Section 15.4: DLEP Data Item Type Codes */
#define DLEP_DIT_RESERVED         0
#define DLEP_DIT_STATUS           1
#define DLEP_DIT_V4CONN           2
#define DLEP_DIT_V6CONN           3
#define DLEP_DIT_PEERTYPE         4
#define DLEP_DIT_HEARTBEAT        5
#define DLEP_DIT_EXTSUPP          6
#define DLEP_DIT_MACADDR          7
#define DLEP_DIT_V4ADDR           8
#define DLEP_DIT_V6ADDR           9
#define DLEP_DIT_V4SUBNET         10
#define DLEP_DIT_V6SUBNET         11
#define DLEP_DIT_MDRR             12
#define DLEP_DIT_MDRT             13
#define DLEP_DIT_CDRR             14
#define DLEP_DIT_CDRT             15
#define DLEP_DIT_LAT              16
#define DLEP_DIT_RES              17
#define DLEP_DIT_RLQR             18
#define DLEP_DIT_RLQT             19
#define DLEP_DIT_MTU              20

/* Section 15.5: DLEP Status Codes */
#define DLEP_SC_CONT_SUCCESS      0
#define DLEP_SC_CONT_NOTINT       1
#define DLEP_SC_CONT_RQSTDENIED   2
#define DLEP_SC_CONT_INCONSIST    3
#define DLEP_SC_TERM_UNKWNMSG     128
#define DLEP_SC_TERM_UNEXPMSG     129
#define DLEP_SC_TERM_INVDATA      130
#define DLEP_SC_TERM_INVDEST      131
#define DLEP_SC_TERM_TIMEDOUT     132
#define DLEP_SC_TERM_SHUTDOWN     255

/* Section 15.6: DLEP Extension Type Codes */
#define DLEP_EXT_RESERVED         0

/* Section 15.7: DLEP IPv4 Connection Point Flags */
#define DLEP_DIT_V4CONN_FLAGMASK_BITLEN     DLEP_DIT_V4CONN_FLAGS_LEN * 8
#define DLEP_DIT_V4CONN_FLAGMASK_TLS        0x01

/* Section 15.8: DLEP IPv6 Connection Point Flags */
#define DLEP_DIT_V6CONN_FLAGMASK_BITLEN     DLEP_DIT_V6CONN_FLAGS_LEN * 8
#define DLEP_DIT_V6CONN_FLAGMASK_TLS        0x01

/* Section 15.9: DLEP Peer Type Flags */
#define DLEP_DIT_PEERTYPE_FLAGMASK_BITLEN   DLEP_DIT_PEERTYPE_FLAGS_LEN * 8
#define DLEP_DIT_PEERTYPE_FLAGMASK_SMI      0x01

/* Section 15.10: DLEP IPv4 Address Flags */
#define DLEP_DIT_V4ADDR_FLAGMASK_BITLEN     DLEP_DIT_V4ADDR_FLAGS_LEN * 8
#define DLEP_DIT_V4ADDR_FLAGMASK_ADDDROP    0x01

/* Section 15.11: DLEP IPv6 Address Flags */
#define DLEP_DIT_V6ADDR_FLAGMASK_BITLEN     DLEP_DIT_V6ADDR_FLAGS_LEN * 8
#define DLEP_DIT_V6ADDR_FLAGMASK_ADDDROP    0x01

/* Section 15.12: DLEP IPv4 Attached Subnet Flags */
#define DLEP_DIT_V4SUBNET_FLAGMASK_BITLEN   DLEP_DIT_V4SUBNET_FLAGS_LEN * 8
#define DLEP_DIT_V4SUBNET_FLAGMASK_ADDDROP  0x01

/* Section 15.13: DLEP IPv6 Attached Subnet Flags */
#define DLEP_DIT_V6SUBNET_FLAGMASK_BITLEN   DLEP_DIT_V6SUBNET_FLAGS_LEN * 8
#define DLEP_DIT_V6SUBNET_FLAGMASK_ADDDROP  0x01

/* Section 15.14: DLEP Well-known Port */
#define DLEP_UDP_PORT 854
#define DLEP_TCP_PORT 854

/* Section 15.15: DLEP IPv4 Link-Local Multicast Address */
#define DLEP_IPV4_ADDR "224.0.0.117"

/* Section 15.16: DLEP IPv6 Link-Local Multicast Address */
#define DLEP_IPV6_ADDR "FF02:0:0:0:0:0:1:7"
