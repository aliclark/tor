/* * Copyright (c) 2012-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.h
 * \brief Header file for channeltls.c
 **/

#ifndef TOR_CHANNELTLS_H
#define TOR_CHANNELTLS_H

#include "or.h"
#include "channel.h"

#include <quux.h>

#define BASE_CHAN_TO_TLS(c) (channel_tls_from_base((c)))
#define TLS_CHAN_TO_BASE(c) (channel_tls_to_base((c)))

#define TLS_CHAN_MAGIC 0x8a192427U

typedef struct streamcirc_s {
  // FIXME: can get rid of this ptr by attaching to stream's conn context
  channel_tls_t* tlschan;
  quux_stream stream;

  // store reads of a partial cell from quic
  uint8_t read_cell_buf[CELL_MAX_NETWORK_SIZE];
  int read_cell_pos;

  // if the quic stream is blocked we may need to park a partial cell here
  // (the write_cell API is boolean around cell writes)
  uint8_t write_cell_buf[CELL_MAX_NETWORK_SIZE];
  int write_cell_pos;

} streamcirc_t;

#ifdef TOR_CHANNEL_INTERNAL_

struct channel_tls_s {
  /* Base channel_t struct */
  channel_t base_;
  /* or_connection_t pointer */
  or_connection_t *conn;

  uint8_t tlssecrets[DIGEST256_LEN];

  streamcircmap_t* streamcircmap;
  quux_peer peer;
  streamcirc_t* control_streamcirc;

  smartlist_t* paused_circuits;

  // unfortunately the flush API is not circuit-centric (yet?)
  int buffered_cs_id:1;
  int needs_flush:1;
};

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

/* Cleanup at shutdown */
void channel_tls_free_all(void);

int channel_tls_write_cell_method(channel_t *chan, cell_t *cell);

extern tlssecretsmap_t *tlssecretsmap;
void quic_accept(quux_stream stream);

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

