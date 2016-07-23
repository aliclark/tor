/* * Copyright (c) 2012-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.h
 * \brief Header file for channeltls.c
 **/

#ifndef TOR_CHANNELTLS_H
#define TOR_CHANNELTLS_H

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#include "or.h"
#include "channel.h"

#define BASE_CHAN_TO_TLS(c) (channel_tls_from_base((c)))
#define TLS_CHAN_TO_BASE(c) (channel_tls_to_base((c)))

#define TLS_CHAN_MAGIC 0x8a192427U

#ifdef TOR_CHANNEL_INTERNAL_

struct channel_tls_s {
  /* Base channel_t struct */
  channel_t base_;
  /* or_connection_t pointer */
  or_connection_t *conn;
  struct UTPSocket *utp;
  buf_t *utp_write_buf;
  buf_t *utp_read_buf;
  int utp_sent_id:1;
  int utp_is_dummy:1;
};

typedef struct utp_packet_t {
  struct utp_packet_t *next;
  const char *bytes;
  size_t len;
  const struct sockaddr *to;
  socklen_t tolen;
} utp_packet_t;

#endif /* TOR_CHANNEL_INTERNAL_ */

channel_t * channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);
channel_listener_t * channel_tls_get_listener(void);
channel_listener_t * channel_tls_start_listener(void);
channel_t * channel_tls_handle_incoming(or_connection_t *orconn);

/* Casts */

channel_t * channel_tls_to_base(channel_tls_t *tlschan);
channel_tls_t * channel_tls_from_base(channel_t *chan);

/* Things for connection_or.c to call back into */
void channel_tls_handle_cell(cell_t *cell, or_connection_t *conn);
void channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                               or_connection_t *conn,
                                               uint8_t old_state,
                                               uint8_t state);
void channel_tls_handle_var_cell(var_cell_t *var_cell,
                                 or_connection_t *conn);
void channel_tls_update_marks(or_connection_t *conn);

/* Things for connection.c to call back into */
void utp_read_callback(evutil_socket_t fd, short what, void *arg);
void utp_write_callback(evutil_socket_t fd, short what, void *arg);

/* Things to be called by libutp. */
typedef uint8_t byte;
typedef int bool;
void tor_UTPOnReadProc(void *userdata, const byte *bytes, size_t count);
void tor_UTPOnWriteProc(void *userdata, byte *bytes, size_t count);
size_t tor_UTPGetRBSize(void *userdata);
void tor_UTPOnStateChangeProc(void *userdata, int state);
void tor_UTPOnErrorProc(void *userdata, int errcode);
void tor_UTPOnOverheadProc(void *userdata, bool send, size_t count,
                           int type);
void tor_UTPSendToProc(void *userdata, const byte *bytes, size_t len,
                       const struct sockaddr *to, socklen_t tolen);
void tor_UTPGotIncomingConnection(void *userdata, struct UTPSocket* s);

/* Cleanup at shutdown */
void channel_tls_free_all(void);

#ifdef CHANNELTLS_PRIVATE
STATIC void channel_tls_process_certs_cell(var_cell_t *cell,
                                           channel_tls_t *tlschan);
STATIC void channel_tls_process_auth_challenge_cell(var_cell_t *cell,
                                                    channel_tls_t *tlschan);
STATIC void channel_tls_common_init(channel_tls_t *tlschan);
STATIC void channel_tls_process_authenticate_cell(var_cell_t *cell,
                                                  channel_tls_t *tlschan);
#endif

#endif

