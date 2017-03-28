/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system. INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		TCP-ENO Definitions
 *
 * Author:	Kyle R. Rose <krose@krose.org>
 *
 * License:     Dual MIT/GPL
 */

/*
   MIT License

   Copyright (C) 2016 Kyle R. Rose

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

   GPL

   This program is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License as published by the Free Software
   Foundation; either version 2 of the License, or (at your option) any later
   version.
*/

#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/types.h>
#include <linux/string.h>

/* TCP ENO (Encryption Negotiation Option) */
/* TODO: Would be nice if this came from linux/tcp.h, but that would create a
   circular dependency. */
#define TCP_ENO_SUBOPTION_MAX 38

struct tcp_eno_syn_subopts  {
	s8	len;			/* Option data length */
	u8	val[TCP_ENO_SUBOPTION_MAX]; /* Option data */
};

/* TODO: Probably want to reference the skb directly for the remote options
   instead of copying them over. This will require some invasive changes and/or
   duck typing */
static inline void tcp_eno_set_syn_subopts(struct tcp_eno_syn_subopts *sso,
					   int len, const u8 *val)
{
	sso->len = max(0, min((int) sizeof(sso->val), len));
	memcpy(sso->val, val, sso->len);
}

/* TCP ENO negotiation state
   This will contain whatever suboptions are sent to the peer.
   TODO: We need to destroy this state when it's no longer needed (e.g., after
   encryption has been negotiated) */
struct tcp_eno {
	struct tcp_eno_syn_subopts sso;	/* Suboptions */
	s8	neg_ofs;		/* Offset of negotiated suboption, or -1 */
	bool	active : 1,		/* Local is active opener */
		role_B : 1,		/* Local is role B */
		remote_enabled : 1;	/* Remote has sent non-SYN ENO segment */
};

/* Initializes the handshake state. Must be called before tcp_eno_negotiate. */
void tcp_eno_init(struct tcp_eno *eno, bool active);

/* Returns true iff negotiation succeeds, setting eno->neg_ofs appropriately. */
bool tcp_eno_negotiate(struct tcp_eno *eno, struct tcp_eno_syn_subopts *r_sso);

static inline const struct tcp_eno_syn_subopts *
tcp_eno_get_syn_subopts(struct tcp_eno *eno)
{
	if (!eno || eno->sso.len < 0)
		return NULL;
	return &eno->sso;
}

static inline void tcp_eno_set_remote_enabled(struct tcp_eno *eno)
{
	eno->remote_enabled = true;
}

static inline bool tcp_eno_has_remote_enabled(struct tcp_eno *eno)
{
	return eno->remote_enabled;
}

int tcp_eno_negotiated_tep(struct tcp_eno *eno);

/* TODO:

   * Allow registration of TEP types along with function pointers for validation
   and state setup
 */
