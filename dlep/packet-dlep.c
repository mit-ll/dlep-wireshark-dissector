/* packet-dlep.c
 * Routines for DLEP protocol packet disassembly
 *
 * $Id$
 *
 * Copyright (C) 2016 Massachusetts Institute of Technology
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

#include "config.h"
#include "packet-dlep.h"

#include <epan/value_string.h>  /* for value_string_ext in epan/ipproto.h
                                 * (not self-contained in wireshark 10.6.1) */

#include <epan/ftypes/ftypes.h> /* for fieldtype lengths */
#include <epan/expert.h>        /* for expert_add_undecoded_item() */
#include <epan/ipproto.h>       /* for IP_PROTO_TCP and IP_PROTO_UDP */
#include <epan/packet.h>
#include <epan/packet_info.h>   /* for struct packet_info */
#include <epan/prefs.h>
#include <epan/tvbuff.h>
#include <glib.h>

static guint global_dlep_udp_port = DLEP_UDP_PORT;
static guint global_dlep_tcp_port = DLEP_TCP_PORT;

void proto_register_dlep(void);
void proto_reg_handoff_dlep(void);

static int proto_dlep = -1;

static int hf_dlep_signal = -1;
static int hf_dlep_signal_type = -1;
static int hf_dlep_signal_length = -1;
static int hf_dlep_message = -1;
static int hf_dlep_message_type = -1;
static int hf_dlep_message_length = -1;
static int hf_dlep_dataitem = -1;
static int hf_dlep_dataitem_type = -1;
static int hf_dlep_dataitem_length = -1;
static int hf_dlep_dataitem_value = -1;
static int hf_dlep_dataitem_status = -1;
static int hf_dlep_dataitem_status_code = -1;
static int hf_dlep_dataitem_status_text = -1;
static int hf_dlep_dataitem_v4conn = -1;
static int hf_dlep_dataitem_v4conn_flags = -1;
static int hf_dlep_dataitem_v4conn_addr = -1;
static int hf_dlep_dataitem_v4conn_port = -1;
static int hf_dlep_dataitem_v6conn = -1;
static int hf_dlep_dataitem_v6conn_flags = -1;
static int hf_dlep_dataitem_v6conn_addr = -1;
static int hf_dlep_dataitem_v6conn_port = -1;
static int hf_dlep_dataitem_peertype = -1;
static int hf_dlep_dataitem_heartbeat = -1;
static int hf_dlep_dataitem_extsupp = -1;
static int hf_dlep_dataitem_extsupp_code = -1;
static int hf_dlep_dataitem_macaddr_eui48 = -1;
static int hf_dlep_dataitem_macaddr_eui64 = -1;
static int hf_dlep_dataitem_v4addr = -1;
static int hf_dlep_dataitem_v4addr_flags = -1;
static int hf_dlep_dataitem_v4addr_flags_adddrop = -1;
static int hf_dlep_dataitem_v4addr_addr = -1;
static int hf_dlep_dataitem_v6addr = -1;
static int hf_dlep_dataitem_v6addr_flags = -1;
static int hf_dlep_dataitem_v6addr_flags_adddrop = -1;
static int hf_dlep_dataitem_v6addr_addr = -1;
static int hf_dlep_dataitem_v4subnet = -1;
static int hf_dlep_dataitem_v4subnet_flags = -1;
static int hf_dlep_dataitem_v4subnet_flags_adddrop = -1;
static int hf_dlep_dataitem_v4subnet_subnet = -1;
static int hf_dlep_dataitem_v4subnet_prefixlen = -1;
static int hf_dlep_dataitem_v6subnet = -1;
static int hf_dlep_dataitem_v6subnet_flags = -1;
static int hf_dlep_dataitem_v6subnet_flags_adddrop = -1;
static int hf_dlep_dataitem_v6subnet_subnet = -1;
static int hf_dlep_dataitem_v6subnet_prefixlen = -1;
static int hf_dlep_dataitem_mdrr = -1;
static int hf_dlep_dataitem_mdrt = -1;
static int hf_dlep_dataitem_cdrr = -1;
static int hf_dlep_dataitem_cdrt = -1;
static int hf_dlep_dataitem_latency = -1;
static int hf_dlep_dataitem_resources = -1;
static int hf_dlep_dataitem_rlqr = -1;
static int hf_dlep_dataitem_rlqt = -1;
static int hf_dlep_dataitem_mtu = -1;

static gint ett_dlep = -1;
static gint ett_dlep_dataitem = -1;
static gint ett_dlep_flags = -1;

static const value_string signal_type_vals[] = {
  { DLEP_SIG_RESERVED,  "Reserved"        },
  { DLEP_SIG_PEERDISC,  "Peer Discovery"  },
  { DLEP_SIG_PEEROFFR,  "Peer Offer"      },
  { 0,                  NULL              }
};

static const value_string message_type_vals[] = {
  { DLEP_MSG_RESERVED,        "Reserved"                        },
  { DLEP_MSG_SESSINIT,        "Session Initialization"          },
  { DLEP_MSG_SESSINITRESP,    "Session Initialization Response" },
  { DLEP_MSG_SESSUPDATE,      "Session Update"                  },
  { DLEP_MSG_SESSUPDATERESP,  "Session Update Response"         },
  { DLEP_MSG_SESSTERM,        "Session Termination"             },
  { DLEP_MSG_SESSTERMRESP,    "Session Termination Response"    },
  { DLEP_MSG_DESTUP,          "Destination Up"                  },
  { DLEP_MSG_DESTUPRESP,      "Destination Up Response"         },
  { DLEP_MSG_DESTANN,         "Destination Announce"            },
  { DLEP_MSG_DESTANNRESP,     "Destination Announce Response"   },
  { DLEP_MSG_DESTDOWN,        "Destination Down"                },
  { DLEP_MSG_DESTDOWNRESP,    "Destination Down Response"       },
  { DLEP_MSG_DESTUPDATE,      "Destination Update"              },
  { DLEP_MSG_LINKCHARRQST,    "Link Characteristics Request"    },
  { DLEP_MSG_LINKCHARRESP,    "Link Characteristics Response"   },
  { DLEP_MSG_HEARTBEAT,       "Heartbeat"                       },
  { 0,                        NULL                              }
};

static const value_string dataitem_type_vals[] = {
  { DLEP_DIT_RESERVED,  "Reserved"                                },
  { DLEP_DIT_STATUS,    "Status"                                  },
  { DLEP_DIT_V4CONN,    "IPv4 Connection Point"                   },
  { DLEP_DIT_V6CONN,    "IPv6 Connection Point"                   },
  { DLEP_DIT_PEERTYPE,  "Peer Type"                               },
  { DLEP_DIT_HEARTBEAT, "Heartbeat Interval"                      },
  { DLEP_DIT_EXTSUPP,   "Extensions Supported"                    },
  { DLEP_DIT_MACADDR,   "MAC Address"                             },
  { DLEP_DIT_V4ADDR,    "IPv4 Address"                            },
  { DLEP_DIT_V6ADDR,    "IPv6 Address"                            },
  { DLEP_DIT_V4SUBNET,  "IPv4 Attached Subnet"                    },
  { DLEP_DIT_V6SUBNET,  "IPv6 Attached Subnet"                    },
  { DLEP_DIT_MDRR,      "Maximum Data Rate (Receive) (MDRR)"      },
  { DLEP_DIT_MDRT,      "Maximum Data Rate (Transmit) (MDRT)"     },
  { DLEP_DIT_CDRR,      "Current Data Rate (Receive) (CDRR)"      },
  { DLEP_DIT_CDRT,      "Current Data Rate (Transmit) (CDRT)"     },
  { DLEP_DIT_LAT,       "Latency"                                 },
  { DLEP_DIT_RES,       "Resources (RES)"                         },
  { DLEP_DIT_RLQR,      "Relative Link Quality (Receive) (RLQR)"  },
  { DLEP_DIT_RLQT,      "Relative Link Quality (Transmit) (RLQT)" },
  { DLEP_DIT_MTU,       "Maximum Transmission Unit (MTU)"         },
  { 0,                  NULL                                      }
};

static const value_string status_code_vals[] = {
  { DLEP_SC_CONT_SUCCESS,     "Success"             },
  { DLEP_SC_CONT_NOTINT,      "Not Interested"      },
  { DLEP_SC_CONT_RQSTDENIED,  "Request Denied"      },
  { DLEP_SC_TERM_UNKWNMSG,    "Unknown Message"     },
  { DLEP_SC_TERM_UNEXPMSG,    "Unexpected Message"  },
  { DLEP_SC_TERM_INVDATA,     "Invalid Data"        },
  { DLEP_SC_TERM_INVDEST,     "Invalid Destination" },
  { DLEP_SC_TERM_TIMEDOUT,    "Timed Out"           },
  { 0,                        NULL                  }
};

static const value_string extension_code_vals[] = {
  { DLEP_EXT_RESERVED,      "Reserved"          },
  { DLEP_EXT_CREDITWINDOW,  "Credit Windowing"  },
  { 0,                      NULL                }
};

static const true_false_string setnotset_tfs = {
  "Set",
  "Not Set"
};

static const true_false_string adddrop_tfs = {
  "Add",
  "Drop"
};

/* Section 11.1: Status */
static int
decode_dataitem_status(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item *tmp_pi = NULL;
  int status_code;

  /* Add and hide the specific dataitem protocol item */
  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_status, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  if (len < DLEP_DIT_STATUS_MINLEN) {
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");
    return offset;
  }

  proto_tree_add_item(pt, hf_dlep_dataitem_status_code, tvb, offset, 1, ENC_BIG_ENDIAN);
  status_code = tvb_get_guint8(tvb, offset);
  proto_item_append_text(pi, ", Code: %s (%u)", val_to_str(status_code, status_code_vals, "Unknown"), status_code);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_status_text, tvb, offset, len-1, ENC_UTF_8);
  proto_item_append_text(pi, ", Text: %s", tvb_get_ephemeral_string(tvb, offset, len-1));
  offset+=len-1;

  return offset;
}

/* Section 11.2: IPv4 Connection Point */
static int
decode_dataitem_v4conn(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4conn, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  proto_tree_add_item(pt, hf_dlep_dataitem_v4conn_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4conn_addr, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", Addr: %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  if (len == DLEP_DIT_V4CONN_WPORT_LEN) {
    proto_tree_add_item(pt, hf_dlep_dataitem_v4conn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, ", Port: %u", tvb_get_ntohs(tvb, offset));
    offset+=2;
  }

  if (len != DLEP_DIT_V4CONN_LEN && len != DLEP_DIT_V4CONN_WPORT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.3: IPv6 Connection Point */
static int
decode_dataitem_v6conn(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6conn, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  proto_tree_add_item(pt, hf_dlep_dataitem_v6conn_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6conn_addr, tvb, offset, FT_IPv6_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", Addr: %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  if (len == DLEP_DIT_V6CONN_WPORT_LEN) {
    proto_tree_add_item(pt, hf_dlep_dataitem_v6conn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, ", Port: %u", tvb_get_ntohs(tvb, offset));
    offset+=2;
  }

  if (len != DLEP_DIT_V6CONN_LEN && len != DLEP_DIT_V6CONN_WPORT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.4: Peer Type */
static int
decode_dataitem_peertype(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_peertype, tvb, offset, len, ENC_UTF_8);
  proto_item_append_text(pi, ": %s", tvb_get_ephemeral_string(tvb, offset, len));
  offset+=len;

  return offset;
}

/* Section 11.5: Heartbeat Interval */
static int
decode_dataitem_heartbeat(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_heartbeat, tvb, offset, DLEP_DIT_HEARTBEAT_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %u (ms)", tvb_get_ntohl(tvb, offset));
  offset+=DLEP_DIT_HEARTBEAT_LEN;

  if (len != DLEP_DIT_HEARTBEAT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.6: Extensions Supported */
static int
decode_dataitem_extsupp(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  int extension_code;

  proto_item* tmp_pi = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_extsupp, tvb, offset, len, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  while(len > 0) {
    extension_code = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_dlep_dataitem_extsupp_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, ", Ext: %s (%u)", val_to_str(extension_code, extension_code_vals, "Unknown"), extension_code);
    offset+=2;
    len-=2;
  }

  return offset;
}

/* Section 11.7: MAC Address */
static int
decode_dataitem_macaddr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  switch(len) {
    case FT_ETHER_LEN:
      proto_tree_add_item(pt, hf_dlep_dataitem_macaddr_eui48, tvb, offset, len, ENC_NA);
      proto_item_append_text(pi, ": %s", tvb_ether_to_str(tvb, offset));
      break;
    case FT_EUI64_LEN:
      proto_tree_add_item(pt, hf_dlep_dataitem_macaddr_eui64, tvb, offset, len, ENC_BIG_ENDIAN);
      proto_item_append_text(pi, ": %s", tvb_eui64_to_str(tvb, offset, ENC_BIG_ENDIAN));
      break;
    default:
      expert_add_undecoded_item(tvb, NULL, pt, offset, len, PI_WARN);
      break;
  }
  offset+=len;

  return offset;
}

/* Section 11.8: IPv4 Address */
static int
decode_dataitem_v4addr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4addr, tvb, offset, DLEP_DIT_V4ADDR_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4addr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v4addr_flags_adddrop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tvb_get_guint8(tvb, offset) & DLEP_DIT_V4ADDR_FLAGS_ADDDROP ? adddrop_tfs.true_string : adddrop_tfs.false_string);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4addr_addr, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  if (len != DLEP_DIT_V4ADDR_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.9: IPv6 Address */
static int
decode_dataitem_v6addr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6addr, tvb, offset, DLEP_DIT_V6ADDR_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6addr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v6addr_flags_adddrop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tvb_get_guint8(tvb, offset) & DLEP_DIT_V6ADDR_FLAGS_ADDDROP ? adddrop_tfs.true_string : adddrop_tfs.false_string);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6addr_addr, tvb, offset, FT_IPv6_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  if (len != DLEP_DIT_V6ADDR_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.10: IPv4 Attached Subnet */
static int
decode_dataitem_v4subnet(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet, tvb, offset, DLEP_DIT_V4SUBNET_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v4subnet_flags_adddrop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tvb_get_guint8(tvb, offset) & DLEP_DIT_V4SUBNET_FLAGS_ADDDROP ? adddrop_tfs.true_string : adddrop_tfs.false_string);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet_subnet, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip_to_str(tvb, offset));
  offset+=FT_IPv4_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v4subnet_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, "/%u", tvb_get_guint8(tvb, offset));
  offset+=1;

  if (len != DLEP_DIT_V6SUBNET_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.11: IPv6 Attached Subnet */
static int
decode_dataitem_v6subnet(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_item* tmp_pi = NULL;
  proto_tree* flags_pt = NULL;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet, tvb, offset, DLEP_DIT_V6SUBNET_LEN, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  tmp_pi = proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_pt = proto_item_add_subtree(tmp_pi, ett_dlep_flags);
  proto_tree_add_item(flags_pt, hf_dlep_dataitem_v6subnet_flags_adddrop, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ", %s:", tvb_get_guint8(tvb, offset) & DLEP_DIT_V6SUBNET_FLAGS_ADDDROP ? adddrop_tfs.true_string : adddrop_tfs.false_string);
  offset+=1;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet_subnet, tvb, offset, FT_IPv6_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, " %s", tvb_ip6_to_str(tvb, offset));
  offset+=FT_IPv6_LEN;

  proto_tree_add_item(pt, hf_dlep_dataitem_v6subnet_prefixlen, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, "/%u", tvb_get_guint8(tvb, offset));
  offset+=1;

  if (len != DLEP_DIT_V6SUBNET_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.12: Maximum Data Rate (Receive) */
static int
decode_dataitem_mdrr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_mdrr, tvb, offset, DLEP_DIT_MDRR_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %lu (bps)", tvb_get_ntoh64(tvb, offset));
  offset+=DLEP_DIT_MDRR_LEN;

  if (len != DLEP_DIT_MDRR_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.13: Maximum Data Rate (Transmit) */
static int
decode_dataitem_mdrt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_mdrt, tvb, offset, DLEP_DIT_MDRT_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %lu (bps)", tvb_get_ntoh64(tvb, offset));
  offset+=DLEP_DIT_MDRT_LEN;

  if (len != DLEP_DIT_MDRT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.14: Current Data Rate (Receive) */
static int
decode_dataitem_cdrr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_cdrr, tvb, offset, DLEP_DIT_CDRR_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %lu (bps)", tvb_get_ntoh64(tvb, offset));
  offset+=DLEP_DIT_CDRR_LEN;

  if (len != DLEP_DIT_CDRR_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.15: Current Data Rate (Transmit) */
static int
decode_dataitem_cdrt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_cdrt, tvb, offset, DLEP_DIT_CDRT_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %lu (bps)", tvb_get_ntoh64(tvb, offset));
  offset+=DLEP_DIT_CDRT_LEN;

  if (len != DLEP_DIT_CDRT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.16: Latency */
static int
decode_dataitem_latency(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_latency, tvb, offset, DLEP_DIT_LAT_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %lu (ms)", tvb_get_ntoh64(tvb, offset));
  offset+=DLEP_DIT_LAT_LEN;

  if (len != DLEP_DIT_LAT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.17: Resources */
static int
decode_dataitem_resources(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_resources, tvb, offset, DLEP_DIT_RES_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %u (%%)", tvb_get_guint8(tvb, offset));
  offset+=DLEP_DIT_RES_LEN;

  if (len != DLEP_DIT_RES_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.18: Relative Link Quality (Receive) */
static int
decode_dataitem_rlqr(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_rlqr, tvb, offset, DLEP_DIT_RLQR_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %u (%%)", tvb_get_guint8(tvb, offset));
  offset+=DLEP_DIT_RLQR_LEN;

  if (len != DLEP_DIT_RLQR_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.19: Relative Link Quality (Transmit) */
static int
decode_dataitem_rlqt(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_rlqt, tvb, offset, DLEP_DIT_RLQT_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %u (%%)", tvb_get_guint8(tvb, offset));
  offset+=DLEP_DIT_RLQT_LEN;

  if (len != DLEP_DIT_RLQT_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/* Section 11.20: Maximum Transmission Unit (MTU) */
static int
decode_dataitem_mtu(tvbuff_t *tvb, int offset, proto_item *pi, proto_tree *pt, int len)
{
  proto_tree_add_item(pt, hf_dlep_dataitem_mtu, tvb, offset, DLEP_DIT_MTU_LEN, ENC_BIG_ENDIAN);
  proto_item_append_text(pi, ": %d (bytes)", tvb_get_ntohs(tvb, offset));
  offset+=DLEP_DIT_MTU_LEN;

  if (len != DLEP_DIT_MTU_LEN)
    expert_add_info_format(NULL, pi, PI_PROTOCOL, PI_WARN, "Invalid Data Item length");

  return offset;
}

/**
 * Section 9.3: DLEP Generic Data Item
 *
 * A note on dataitem decoding:
 *
 * When decoding a specific dataitem, we append information to the generic
 * dataitem's protocol display line using proto_item_append_test. This is 
 * intended to provide a one-line summary of the specific dataitem without
 * needing to open the corresponding subtree. The pattern is to typically
 * augment the one-line summary as each piece of the specific dataitem is
 * decoded.
 *
 * Additionally, we often create a hidden proto_item under the generic
 * dataitem tree that can be used for filtering on the specific dataitem name.
 * Subfields of the specific dataitem are then placed under the generic
 * dataitem tree. For example, the following filter 'dlep.dataitem.status' is
 * valid, but the protocol tree display places 'dlep.dataitem.status.code' 
 * under 'dlep.dataitem'. For very simple dataitems (e.g., Heartbeat Interval),
 * there is only one subfield, and this step is skipped.
 */
static int
decode_dataitem(tvbuff_t *tvb, int offset, proto_tree *pt)
{
  proto_item *dataitem_pi = NULL;
  proto_tree *dataitem_pt = NULL;
  int dataitem_type       = 0;
  int dataitem_length     = 0;

  dataitem_type   = tvb_get_ntohs(tvb, offset);
  dataitem_length = tvb_get_ntohs(tvb, offset+2);

  dataitem_pi = proto_tree_add_item(pt, hf_dlep_dataitem, tvb, offset, 2+2+dataitem_length, ENC_NA);
  dataitem_pt = proto_item_add_subtree(dataitem_pi, ett_dlep_dataitem);

  /* Start the one-line description of the data item */
  proto_item_set_text(dataitem_pi, "%s Data Item", val_to_str(dataitem_type, dataitem_type_vals, "Unknown"));

  /* Add supporting fields underneath */
  proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  switch(dataitem_type) {
    case DLEP_DIT_STATUS:
      offset=decode_dataitem_status(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V4CONN:
      offset=decode_dataitem_v4conn(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V6CONN:
      offset=decode_dataitem_v6conn(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
   case DLEP_DIT_PEERTYPE:
      offset=decode_dataitem_peertype(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_HEARTBEAT:
      offset=decode_dataitem_heartbeat(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_EXTSUPP:
      offset=decode_dataitem_extsupp(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_MACADDR:
      offset=decode_dataitem_macaddr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V4ADDR:
      offset=decode_dataitem_v4addr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V6ADDR:
      offset=decode_dataitem_v6addr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V4SUBNET:
      offset=decode_dataitem_v4subnet(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_V6SUBNET:
      offset=decode_dataitem_v6subnet(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_MDRR:
      offset=decode_dataitem_mdrr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_MDRT:
      offset=decode_dataitem_mdrt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_CDRR:
      offset=decode_dataitem_cdrr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_CDRT:
      offset=decode_dataitem_cdrt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_LAT:
      offset=decode_dataitem_latency(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_RES:
      offset=decode_dataitem_resources(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_RLQR:
      offset=decode_dataitem_rlqr(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_RLQT:
      offset=decode_dataitem_rlqt(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    case DLEP_DIT_MTU:
      offset=decode_dataitem_mtu(tvb, offset, dataitem_pi, dataitem_pt, dataitem_length);
      break;
    default:
      proto_tree_add_item(dataitem_pt, hf_dlep_dataitem_value, tvb, offset, dataitem_length, ENC_NA);
      offset+=dataitem_length;
  };

  return offset;
}

/* Section 9.1: DLEP Signal Header */
static int
decode_signal_header(tvbuff_t *tvb, int offset, proto_item* pi, proto_tree *pt)
{
  proto_item *tmp_pi = NULL;
  int signal_type;
  int signal_length;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_signal, tvb, offset, 0, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  offset+=4; /* Skip 4-byte "DLEP" */

  proto_tree_add_item(pt, hf_dlep_signal_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  signal_type = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ", Signal: %s (%u)", val_to_str(signal_type, signal_type_vals, "Unknown"), signal_type);
  offset+=2;

  signal_length = tvb_get_ntohs(tvb, offset);
  tmp_pi = proto_tree_add_item(pt, hf_dlep_signal_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  if (signal_length != tvb_reported_length_remaining(tvb, offset))
    expert_add_info_format(NULL, tmp_pi, PI_PROTOCOL, PI_WARN, "Signal length does not match reported length remaining");

  return offset;
}

/* Section 9.2: DLEP Message Header */
static int
decode_message_header(tvbuff_t *tvb, int offset, proto_item* pi, proto_tree *pt)
{
  proto_item *tmp_pi = NULL;
  int message_type;
  int message_length;

  tmp_pi = proto_tree_add_item(pt, hf_dlep_message, tvb, offset, 0, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(tmp_pi);

  proto_tree_add_item(pt, hf_dlep_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  message_type = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ", Message: %s (%u)", val_to_str(message_type, message_type_vals, "Unknown"), message_type);
  offset+=2;

  message_length = tvb_get_ntohs(tvb, offset);
  tmp_pi = proto_tree_add_item(pt, hf_dlep_message_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset+=2;

  if (message_length != tvb_reported_length_remaining(tvb, offset))
    expert_add_info_format(NULL, tmp_pi, PI_PROTOCOL, PI_WARN, "Message length does not match reported length remaining");

  return offset;
}

static void
dissect_dlep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt)
{
  int         offset            = 0;
  proto_item *dlep_pi           = NULL;
  proto_tree *dlep_pt           = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLEP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  if (pt == NULL) {
    return;
  }

  dlep_pi = proto_tree_add_item(pt, proto_dlep, tvb, 0, -1, ENC_NA);
  dlep_pt = proto_item_add_subtree(dlep_pi, ett_dlep);

  /* decode dlep header */
  switch (pinfo->ipproto) {
    case IP_PROTO_TCP:
      offset = decode_message_header(tvb, offset, dlep_pi, dlep_pt);
      break;
    case IP_PROTO_UDP:
      offset = decode_signal_header(tvb, offset, dlep_pi, dlep_pt);
      break;
    default:
      /* DLEP runs only atop TCP and UDP... */
      DISSECTOR_ASSERT_NOT_REACHED();
      break;
  }

  /* decode dlep dataitems */
  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    offset = decode_dataitem(tvb, offset, dlep_pt);
  }
}

void
proto_register_dlep(void)
{
  module_t *dlep_module;

  static hf_register_info hf[] = {
    /* name, abbrev, type, display, strings, bitmask, blurb */
    { &hf_dlep_signal,
      { "Signal", "dlep.signal", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_signal_type,
      { "Signal Type", "dlep.signal.type", FT_UINT16, BASE_DEC, VALS(signal_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_signal_length,
      { "Signal Length (bytes)", "dlep.signal.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_message,
      { "Message", "dlep.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_message_type,
      { "Message Type", "dlep.message.type", FT_UINT16, BASE_DEC, VALS(message_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_message_length,
      { "Message Length (bytes)", "dlep.message.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem,
      { "Data Item", "dlep.dataitem", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_type,
      { "Type", "dlep.dataitem.type", FT_UINT16, BASE_DEC, VALS(dataitem_type_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_length,
      { "Length (bytes)", "dlep.dataitem.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_value,
      { "Value", "dlep.dataitem.value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status,
      { "Status", "dlep.dataitem.status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status_code,
      { "Code", "dlep.dataitem.status.code", FT_UINT8, BASE_DEC, VALS(status_code_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_status_text,
      { "Text", "dlep.dataitem.status.text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn,
      { "IPv4 Connection Point", "dlep.dataitem.v4conn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_flags,
      { "Flags", "dlep.dataitem.v4conn.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_addr,
      { "Address", "dlep.dataitem.v4conn.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4conn_port,
      { "Port", "dlep.dataitem.v4conn.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn,
      { "IPv6 Connection Point", "dlep.dataitem.v6conn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_flags,
      { "Flags", "dlep.dataitem.v6conn.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_addr,
      { "Address", "dlep.dataitem.v6conn.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6conn_port,
      { "Port", "dlep.dataitem.v6conn.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_peertype,
      { "Peer Type", "dlep.dataitem.peertype", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_heartbeat,
      { "Heartbeat Interval (ms)", "dlep.dataitem.heartbeat", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_extsupp,
      { "Extensions Supported", "dlep.dataitem.extsupp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_extsupp_code,
      { "Code", "dlep.dataitem.extsupp.code", FT_UINT32, BASE_DEC, VALS(extension_code_vals), 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_macaddr_eui48,
      { "MAC Address", "dlep.dataitem.macaddr", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_macaddr_eui64,
      { "MAC Address", "dlep.dataitem.macaddr", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr,
      { "IPv4 Address", "dlep.dataitem.v4addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_flags,
      { "Flags", "dlep.dataitem.v4addr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_flags_adddrop,
      { "Add/Drop Flag", "dlep.dataitem.v4addr.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V4ADDR_FLAGS_WIDTH, TFS(&adddrop_tfs), DLEP_DIT_V4ADDR_FLAGS_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4addr_addr,
      { "Address", "dlep.dataitem.v4addr.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr,
      { "IPv6 Address", "dlep.dataitem.v6addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_flags,
      { "Flags", "dlep.dataitem.v6addr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_flags_adddrop,
      { "Add/Drop Flag", "dlep.dataitem.v6addr.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V6ADDR_FLAGS_WIDTH, TFS(&adddrop_tfs), DLEP_DIT_V6ADDR_FLAGS_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6addr_addr,
      { "Address", "dlep.dataitem.v6addr.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet,
      { "IPv4 Attached Subnet", "dlep.dataitem.v4subnet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_flags,
      { "Flags", "dlep.dataitem.v4subnet.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_flags_adddrop,
      { "Add/Drop Flag", "dlep.dataitem.v4subnet.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V4SUBNET_FLAGS_WIDTH, TFS(&adddrop_tfs), DLEP_DIT_V4SUBNET_FLAGS_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_subnet,
      { "Subnet", "dlep.dataitem.v4subnet.subnet", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v4subnet_prefixlen,
      { "Prefix Length", "dlep.dataitem.v4subnet.prefixlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet,
      { "IPv6 Attached Subnet", "dlep.dataitem.v6subnet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_flags,
      { "Flags", "dlep.dataitem.v6subnet.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_flags_adddrop,
      { "Add/Drop Flag", "dlep.dataitem.v6subnet.flags.adddrop", FT_BOOLEAN, DLEP_DIT_V6SUBNET_FLAGS_WIDTH, TFS(&adddrop_tfs), DLEP_DIT_V6SUBNET_FLAGS_ADDDROP, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_subnet,
      { "Subnet", "dlep.dataitem.v6subnet.subnet", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_v6subnet_prefixlen,
      { "Prefix Length", "dlep.dataitem.v6subnet.prefixlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mdrr,
      { "Maximum Data Rate (Receive) (bps)", "dlep.dataitem.mdrr", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mdrt,
      { "Maximum Data Rate (Transmit) (bps)", "dlep.dataitem.mdrt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_cdrr,
      { "Current Data Rate (Receive) (bps)", "dlep.dataitem.cdrr", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_cdrt,
      { "Current Data Rate (Transmit) (bps)", "dlep.dataitem.cdrt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_latency,
      { "Latency (ms)", "dlep.dataitem.latency", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_resources,
      { "Resources (\%)", "dlep.dataitem.resources", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_rlqr,
      { "Relative Link Quality (Receive) (\%)", "dlep.dataitem.rlqr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_rlqt,
      { "Relative Link Quality (Transmit) (\%)", "dlep.dataitem.rlqt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dlep_dataitem_mtu,
      { "Maximum Transmission Unit (bytes)", "dlep.dataitem.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_dlep,
    &ett_dlep_dataitem,
    &ett_dlep_flags
  };

  proto_dlep = proto_register_protocol("Dynamic Link Exchange Protocol", "DLEP", "dlep");

  proto_register_field_array(proto_dlep, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dlep_module = prefs_register_protocol(proto_dlep, proto_reg_handoff_dlep);

  prefs_register_uint_preference(dlep_module, "udp.port" ,"DLEP UDP Port", "Set the port for DLEP UDP signals", 10, &global_dlep_udp_port);
  prefs_register_uint_preference(dlep_module, "tcp.port" ,"DLEP TCP Port", "Set the port for DLEP TCP messages", 10, &global_dlep_tcp_port);
}

void
proto_reg_handoff_dlep(void)
{
  static gboolean dlep_prefs_initialized = FALSE;
  static dissector_handle_t dlep_handle;
  static guint dlep_udp_port;
  static guint dlep_tcp_port;

  if (!dlep_prefs_initialized) {
    dlep_handle = create_dissector_handle(dissect_dlep, proto_dlep);

    dlep_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint("udp.port", dlep_udp_port, dlep_handle);
    dissector_delete_uint("tcp.port", dlep_tcp_port, dlep_handle);
  }

  dlep_udp_port = global_dlep_udp_port;
  dlep_tcp_port = global_dlep_tcp_port;

  dissector_add_uint("udp.port", dlep_udp_port, dlep_handle);
  dissector_add_uint("tcp.port", dlep_tcp_port, dlep_handle);
}
