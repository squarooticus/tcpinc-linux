/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system. INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		TCP-ENO Implementation
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

#include <net/tcp_eno.h>

#define SUBOPT_KIND_GLOBAL	0
#define SUBOPT_KIND_TEP_NO_DATA	1
#define SUBOPT_KIND_LENGTH_BYTE	2
#define SUBOPT_KIND_TEP_W_DATA	3

#define subopt_v(b)		(!!((b) & 0x80))
#define subopt_glt(b)		((b) & 0x7F)

static inline int subopt_kind(const u8 c)
{
	int v = subopt_v(c);
	int glt = subopt_glt(c);

	if (!v) {
		if (glt < 0x20)
			return SUBOPT_KIND_GLOBAL;
		else
			return SUBOPT_KIND_TEP_NO_DATA;
	} else {
		if (glt < 0x20)
			return SUBOPT_KIND_LENGTH_BYTE;
		else
			return SUBOPT_KIND_TEP_W_DATA;
	}
}

static inline const u8 *soiter_end(const struct tcp_eno_syn_subopts *subopts)
{
	if (subopts->len == -1)
		return NULL;
	return subopts->val + subopts->len;
}

static inline const u8 *soiter_begin(const struct tcp_eno_syn_subopts *subopts)
{
	if (subopts->len == -1)
		return soiter_end(subopts);
	return subopts->val;
}

static inline const u8 *__soiter_plus(const struct tcp_eno_syn_subopts *subopts,
				      const u8 *iter, int bytes)
{
	if (bytes > 0 && iter != soiter_end(subopts)) {
		iter += bytes;
		if (iter < subopts->val // unlikely overflow
		    || iter > subopts->val + subopts->len)
			iter = soiter_end(subopts);
	}
	return iter;
}

static inline const u8 *soiter_next(const struct tcp_eno_syn_subopts *subopts,
				    const u8 *iter)
{
	if (iter != soiter_end(subopts))
		switch (subopt_kind(*iter)) {
		case SUBOPT_KIND_GLOBAL:
		case SUBOPT_KIND_TEP_NO_DATA:
			iter = __soiter_plus(subopts, iter, 1);
			break;
		case SUBOPT_KIND_LENGTH_BYTE:
			iter = __soiter_plus(subopts, iter,
					     subopt_glt(*iter) + 3);
			break;
		default:
			iter = soiter_end(subopts);
		}

	return iter;
}

static inline int soiter_to_ofs(const struct tcp_eno_syn_subopts *subopts,
				const u8 *iter)
{
	return iter - subopts->val;
}

static inline const u8 *
soiter_from_ofs(const struct tcp_eno_syn_subopts *subopts, int ofs)
{
	const u8 *iter = soiter_begin(subopts);
	return __soiter_plus(subopts, iter, ofs);
}

static inline int soiter_tep_id(const struct tcp_eno_syn_subopts *subopts,
				const u8 *iter)
{
	if (iter != soiter_end(subopts))
		switch (subopt_kind(*iter)) {
		case SUBOPT_KIND_LENGTH_BYTE:
			iter = __soiter_plus(subopts, iter, 1);
			if (iter == soiter_end(subopts)
			    || subopt_kind(*iter) != SUBOPT_KIND_TEP_W_DATA)
				return -1;
			/* Now iter points to the TEP ID byte */
		case SUBOPT_KIND_TEP_W_DATA:
		case SUBOPT_KIND_TEP_NO_DATA:
			return subopt_glt(*iter);
		}

	return -1;
}

static inline int soiter_data(const struct tcp_eno_syn_subopts *subopts,
			      const u8 *iter, const u8 **subopt_data)
{
	const u8 *length_byte;
	int data_len;

	if (iter != soiter_end(subopts))
		switch (subopt_kind(*iter)) {
		case SUBOPT_KIND_LENGTH_BYTE:
			length_byte = iter;
			iter = __soiter_plus(subopts, iter, 1);
			if (iter == soiter_end(subopts)
			    || subopt_kind(*iter) != SUBOPT_KIND_TEP_W_DATA)
				return -1;
			iter = __soiter_plus(subopts, iter, 1);
			*subopt_data = iter;
			data_len = subopt_glt(*length_byte) + 1;
			iter = __soiter_plus(subopts, iter, data_len);
			if (iter - *subopt_data != data_len)
				return -1;
			return data_len;
		case SUBOPT_KIND_TEP_W_DATA:
			iter = __soiter_plus(subopts, iter, 1);
			*subopt_data = iter;
			return soiter_end(subopts) - iter;
		case SUBOPT_KIND_TEP_NO_DATA:
			return 0;
		}

	return -1;
}

static inline u8 global_subopt(const struct tcp_eno_syn_subopts *subopts)
{
	const u8 *iter = soiter_begin(subopts);
	while (iter != soiter_end(subopts)) {
		if (subopt_kind(*iter) == SUBOPT_KIND_GLOBAL)
			return *iter;
		iter = soiter_next(subopts, iter);
	}
	return 0;
}

static inline bool is_tep_data_valid(const struct tcp_eno_syn_subopts *sso_A,
				     const struct tcp_eno_syn_subopts *sso_B,
				     int cand_tep_id,
				     const u8 *iter_A, const u8 *iter_B)
{
	const u8 *tep_data_B;
	int tep_data_len_B = soiter_data(sso_B, iter_B, &tep_data_B);
	const u8 *tep_data_A;
	int tep_data_len_A = soiter_data(sso_A, iter_A, &tep_data_A);
	/* TODO: We don't do suboption data yet for TEPs (e.g., resumption SIDs
	   for tcpcrypt), but this will eventually need hooks into the TEP API
	   for validation */
	return tep_data_len_A == 0 && tep_data_len_B == 0;
}

static inline const u8 *
valid_tep_for_A(const struct tcp_eno_syn_subopts *sso_A,
		const struct tcp_eno_syn_subopts *sso_B,
		int cand_tep_id, const u8 *iter_B)
{
	const u8 *iter_A = soiter_begin(sso_A);
	while (iter_A != soiter_end(sso_A)) {
		if (soiter_tep_id(sso_A, iter_A) == cand_tep_id
		    && is_tep_data_valid(sso_A, sso_B, cand_tep_id, iter_A,
					 iter_B))
			return iter_A;
		iter_A = soiter_next(sso_A, iter_A);
	}
	return soiter_end(sso_A);
}

static inline void set_negotiated_tep(struct tcp_eno *eno,
				      const u8 *neg_iter)
{
	struct tcp_eno_syn_subopts *sso = &eno->sso;
	if (eno->active) {
		/* This is the simple case: we've already sent our ENO
		   suboptions, so we just record the right offset */
		/* TODO: not clear if we need something more than an offset, if
		   a TEP defines repeated suboptions of the same type. */
		eno->neg_ofs = soiter_to_ofs(sso, neg_iter);
	} else {
		/* We need to rewrite the suboptions to include only the global
		   suboption and the negotiated suboption, along with whatever
		   data the TEP wants to send to the client. */
		/* TODO: let the TEPs choose the content of the response. */
		u8 gso = global_subopt(sso);
		u8 tep_id_no_v = soiter_tep_id(sso, neg_iter);
		sso->len = 2;
		sso->val[0] = gso;
		sso->val[1] = tep_id_no_v;
		eno->neg_ofs = 1;
	}
}

static inline void negotiate_tep(struct tcp_eno_syn_subopts *sso_A,
				 struct tcp_eno_syn_subopts *sso_B,
				 const u8 **neg_iter_A, const u8 **neg_iter_B)
{
	/* TODO: iterating backward along role B's TEP list and choosing the
	   first match may be more efficient when there is more than one entry
	   in that list (e.g., for simultaneous open) */
	/* TODO: negotiation is TEP-specific, so we need to validate each
	   suboption with the corresponding TEP module before accepting it */
	/* TODO: probably also need to collect multiple of same suboption and
	   deliver them all to the TEP validation routine, rather than doing a
	   simple iteration like this, since the meaning of repeated suboptions
	   is TEP-specific */
	/* This function is intentionally symmetric (no reference to which is
	   local or which is remote) in an effort to require both sides to agree
	   on the outcome. It will take much care on the part of TEP designers
	   to avoid spurious ENO disables in the case of simultaneous open (if a
	   particular TEP wishes to support SO). */
	const u8 *iter_B = soiter_begin(sso_B);
	if (neg_iter_A)
		*neg_iter_A = soiter_end(sso_A);
	if (neg_iter_B)
		*neg_iter_B = soiter_end(sso_B);
	printk(KERN_CRIT "ENO: sso_A: %*ph\n", sso_A->len, sso_A->val);
	printk(KERN_CRIT "ENO: sso_B: %*ph\n", sso_B->len, sso_B->val);
	while (iter_B != soiter_end(sso_B)) {
		const u8 *iter_A;
		int cand_tep_id = soiter_tep_id(sso_B, iter_B);
		if (cand_tep_id != -1
		    && (iter_A = valid_tep_for_A(sso_A, sso_B, cand_tep_id,
						 iter_B)) != soiter_end(sso_A)) {
			if (neg_iter_A)
				*neg_iter_A = iter_A;
			if (neg_iter_B)
				*neg_iter_B = iter_B;
		}
		iter_B = soiter_next(sso_B, iter_B);
	}
}

#define TCP_ENO_GSO_ROLE_B	0x01
#define TCP_ENO_GSO_APP_AWARE	0x02

static void set_syn_subopts(int len, const u8 *val,
			    struct tcp_eno_syn_subopts *subopts)
{
	if (len >= 0 && len <= TCP_ENO_SUBOPTION_MAX) {
		memcpy(subopts->val, val, len);
		subopts->len = len;
	} else {
		subopts->len = -1;
	}
}

/* TODO: These need to be configurable via /proc and given proper defaults */
static const u8 eno_active_sso_default[] = { 0x21, 0x23, 0x35 };
static const u8 eno_passive_sso_default[] = { TCP_ENO_GSO_ROLE_B, 0x21, 0x23, 0x36 };

void tcp_eno_init(struct tcp_eno *eno, bool active)
{
	/* TODO: Need a mechanism for tweaking default suboptions */
	memset(eno, 0, sizeof(*eno));
	if (active) {
		set_syn_subopts(sizeof(eno_active_sso_default),
				eno_active_sso_default, &eno->sso);
	} else {
		set_syn_subopts(sizeof(eno_passive_sso_default),
				eno_passive_sso_default, &eno->sso);
		eno->role_B = true;
	}
	eno->neg_ofs = -1;
}

bool tcp_eno_negotiate(struct tcp_eno *eno, struct tcp_eno_syn_subopts *r_sso)
{
	const u8 *neg_iter;
	if (eno->role_B)
		negotiate_tep(r_sso, &eno->sso, NULL, &neg_iter);
	else
		negotiate_tep(&eno->sso, r_sso, &neg_iter, NULL);
	if (neg_iter != soiter_end(&eno->sso)) {
		set_negotiated_tep(eno, neg_iter);
		return true;
	} else
		return false;
}

int tcp_eno_negotiated_tep(struct tcp_eno *eno)
{
	const u8 *iter;

	if (eno->neg_ofs == -1)
		return -1;
	iter = soiter_from_ofs(&eno->sso, eno->neg_ofs);
	return soiter_tep_id(&eno->sso, iter);
}
