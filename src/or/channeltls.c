/* * Copyright (c) 2012-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.c
 * \brief channel_t concrete subclass using or_connection_t
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define TOR_CHANNEL_INTERNAL_

#define CHANNELTLS_PRIVATE

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"
#include "circuitstats.h"
#include "command.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "link_handshake.h"
#include "relay.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "scheduler.h"

/** How many CELL_PADDING cells have we received, ever? */
uint64_t stats_n_padding_cells_processed = 0;
/** How many CELL_VERSIONS cells have we received, ever? */
uint64_t stats_n_versions_cells_processed = 0;
/** How many CELL_NETINFO cells have we received, ever? */
uint64_t stats_n_netinfo_cells_processed = 0;
/** How many CELL_VPADDING cells have we received, ever? */
uint64_t stats_n_vpadding_cells_processed = 0;
/** How many CELL_CERTS cells have we received, ever? */
uint64_t stats_n_certs_cells_processed = 0;
/** How many CELL_AUTH_CHALLENGE cells have we received, ever? */
uint64_t stats_n_auth_challenge_cells_processed = 0;
/** How many CELL_AUTHENTICATE cells have we received, ever? */
uint64_t stats_n_authenticate_cells_processed = 0;
/** How many CELL_AUTHORIZE cells have we received, ever? */
uint64_t stats_n_authorize_cells_processed = 0;

/** Active listener, if any */
channel_listener_t *channel_tls_listener = NULL;

/* channel_tls_t method declarations */

static void channel_tls_close_method(channel_t *chan);
static const char * channel_tls_describe_transport_method(channel_t *chan);
static void channel_tls_free_method(channel_t *chan);
static double channel_tls_get_overhead_estimate_method(channel_t *chan);
static int
channel_tls_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out);
static int
channel_tls_get_transport_name_method(channel_t *chan, char **transport_out);
static const char *
channel_tls_get_remote_descr_method(channel_t *chan, int flags);
static int channel_tls_has_queued_writes_method(channel_t *chan);
static int channel_tls_is_canonical_method(channel_t *chan, int req);
static int
channel_tls_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info);
static int channel_tls_matches_target_method(channel_t *chan,
                                             const tor_addr_t *target);
static int channel_tls_num_cells_writeable_method(channel_t *chan);
static size_t channel_tls_num_bytes_queued_method(channel_t *chan);
static int channel_tls_write_packed_cell_method(channel_t *chan,
                                                packed_cell_t *packed_cell);
static int channel_tls_write_var_cell_method(channel_t *chan,
                                             var_cell_t *var_cell);

/* channel_listener_tls_t method declarations */

static void channel_tls_listener_close_method(channel_listener_t *chan_l);
static const char *
channel_tls_listener_describe_transport_method(channel_listener_t *chan_l);

/** Handle incoming cells for the handshake stuff here rather than
 * passing them on up. */

static void channel_tls_process_versions_cell(var_cell_t *cell,
                                              channel_tls_t *tlschan);
static void channel_tls_process_netinfo_cell(cell_t *cell,
                                             channel_tls_t *tlschan);
static int command_allowed_before_handshake(uint8_t command);
static int enter_v3_handshake_with_cell(var_cell_t *cell,
                                        channel_tls_t *tlschan);

static uint32_t net_get_uint32(uint8_t* src) {
  return (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
}
static uint16_t net_get_uint16(uint8_t* src) {
  return (src[0] << 8) | src[1];
}

/*
 * TODO: Nb. The scheduler will be trying to do its thing on the TLS connection,
 * so some additional work may be needed to make it work properly with QUIC.
 *
 * To get equivalent comparison, may need to compare with the scheduler disabled.
 */

/*
 *
 * The following write_*cell methods will only be called
 * once the channel is in state OPEN, which also only happens after
 * the process VERSIONS has placed tlssecrets on the chan on each side
 *
 *
 * For demo purposes, we have a very dumb circuit creation logic
 * whereby if we see a circ_id for which no stream exists yet
 * we create a new stream for it.
 *
 */

/**
 * NB. protocol change: there is no longer a guaranteed happens-after
 * for cell writes to control circuit vs. other circuits.
 *
 * If a dependency does exist some other change may be needed, like
 * duplicating the control cell to all of the affected circuit streams.
 */

/*
 * count must be <= CELL_MAX_NETWORK_SIZE
 *
 * Return  1 if there was no buffer and we managed to write it all
 * Return  0 if there was no buffer but we only achieved partial write
 * Return -1 is there was already a buffer; the write is completely rejected
 */
static int streamcirc_attempt_write(streamcirc_t* sctx, const uint8_t* src, size_t count) {

  tor_assert(count <= CELL_MAX_NETWORK_SIZE);

  if (buf_datalen(sctx->write_cell_buf) != 0) {
#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC won't write because data is already pending");
#endif
    write_to_buf((char*)src, count, sctx->write_cell_buf);
    return 0;
  }

  quux_stream stream = sctx->stream;

  int pos = 0;
  while (pos < count) {
    int remaining = count - pos;
    int bytes_wrote = quux_write(stream, src + pos, remaining);

    if (!bytes_wrote) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC paused during attempted write");
#endif
      write_to_buf((char*)src + pos, remaining, sctx->write_cell_buf);
      return 0;
    }

    pos += bytes_wrote;
#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC wrote part of the attempted write");
#endif
  }

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC attempted write successful");
#endif

#if 0
  // Change the scheduler from waiting_for_write back to pending
  connection_or_flushed_some(sctx->tlschan->conn);
  channel_notify_flushed(TLS_CHAN_TO_BASE(sctx->tlschan));
#endif

  return 1;
}

static void streamcirc_continue_write(quux_stream stream) {
  streamcirc_t* sctx = quux_get_stream_context(stream);

  size_t initial_size = buf_datalen(sctx->write_cell_buf);
  size_t buf_flushlen = initial_size;

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC continuing write %p %zu", sctx->tlschan, initial_size);
#endif

  int written = flush_buf_quic(stream, sctx->write_cell_buf, initial_size,
                &buf_flushlen);

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC wrote %p %d", sctx->tlschan, written);
#endif

  if (written == initial_size && sctx->tlschan->needs_flush) {

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC flushing its pending cells");
#endif
    sctx->tlschan->needs_flush = 0;
    channel_flush_cells(TLS_CHAN_TO_BASE(sctx->tlschan));
    channel_notify_flushed(TLS_CHAN_TO_BASE(sctx->tlschan));
    scheduler_channel_wants_writes(TLS_CHAN_TO_BASE(sctx->tlschan));

#if 0
    channel_flush_cells(TLS_CHAN_TO_BASE(sctx->tlschan));

    //connection_or_flushed_some(sctx->tlschan->conn);
    if (TOR_SIMPLEQ_EMPTY(&TLS_CHAN_TO_BASE(sctx->tlschan)->outgoing_queue)) {
      channel_notify_flushed(TLS_CHAN_TO_BASE(sctx->tlschan));
      // Change the scheduler from waiting_for_write back to pending
      scheduler_channel_wants_writes(TLS_CHAN_TO_BASE(sctx->tlschan));

    } else {
      // Presumably the queue ab
      sctx->tlschan->needs_flush = 1;
    }
#endif
  }
}

/*
 * XXX: 'channel_tls_handle_var_cell' doesn't directly give feedback
 * to tell us to stop and start reading cells off the network
 * if the queues ahead are getting blocked.
 *
 * I think this might be done some other place by taking the TLS socket
 * of the reading or active list, but that wouldn't help in our case
 * because we're using a different socket.
 *
 * Perhaps need to look into that bit of code and get it to do more stuff.
 */
static void streamcirc_continue_read(quux_stream stream) {

  streamcirc_t* sctx = quux_get_stream_context(stream);

  channel_tls_t *tlschan = sctx->tlschan;

  if (CHANNEL_IS_ERROR(TLS_CHAN_TO_BASE(tlschan)) || CHANNEL_IS_CLOSED(TLS_CHAN_TO_BASE(tlschan))) {
#if QUUX_LOG
    log_debug(LD_CHANNEL, "[warn] QUIC ignoring read for closed/error'd conn %p", tlschan);
#endif
    return;
  }

  int wide_circ_ids = tlschan->conn->wide_circ_ids;
  size_t cell_network_size = get_cell_network_size(wide_circ_ids);
  uint8_t* read_buf = sctx->read_cell_buf;

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC continuing cell reads, chan %p", tlschan);
#endif

  if (!sctx->read_cell_pos) {
    for (;;) {
      // superfast case: try to read directly from QUIC's data buffers
      uint8_t* read_ref = quux_peek_reference(stream, cell_network_size);

      if (!read_ref) {
        break;
      }

      // need this one?
      channel_timestamp_active(TLS_CHAN_TO_BASE(tlschan));
      circuit_build_times_network_is_live(get_circuit_build_times_mutable());

      cell_t cell;
      cell_unpack(&cell, (char*)read_ref, wide_circ_ids);

  #if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC peeked a full %s cell, chan %p", cell_command_to_string(cell.command), tlschan);
  #endif
      quux_read_consume(stream, cell_network_size);

      channel_tls_handle_cell(&cell, tlschan->conn);
    }
  }

  for (;;) {
    int bytes_read = quux_read(stream, read_buf + sctx->read_cell_pos, cell_network_size - sctx->read_cell_pos);

    if (!bytes_read) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC paused during cell reads, chan %p", tlschan);
#endif
      return;
    }
    sctx->read_cell_pos += bytes_read;

    if (sctx->read_cell_pos < cell_network_size) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC read a partial cell, chan %p", tlschan);
#endif
      continue;
    }

    // need this one?
    channel_timestamp_active(TLS_CHAN_TO_BASE(tlschan));
    circuit_build_times_network_is_live(get_circuit_build_times_mutable());

    cell_t cell;
    cell_unpack(&cell, (char*)read_buf, wide_circ_ids);

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC read a full %s cell, chan %p", cell_command_to_string(cell.command), tlschan);
#endif
    sctx->read_cell_pos = 0;

    channel_tls_handle_cell(&cell, tlschan->conn);
  }
}

/**
 * It's not pretty to have this logic, but I can't think of a much better
 * solution except maybe having one control stream for each direction
 */
static int maybe_get_cs_shift(channel_tls_t *tlschan, circid_t circ_id) {
  if (circ_id != 0 || !tlschan->buffered_cs_id) {
    return 0;
  }
  return get_circ_id_size(tlschan->conn->wide_circ_ids);
}

static void maybe_clear_cs_shift(channel_tls_t *tlschan, circid_t circ_id) {
  if (circ_id != 0) {
    return;
  }
  tlschan->buffered_cs_id = 0;
}

static streamcirc_t* channel_tls_get_streamcirc(channel_tls_t *tlschan, circid_t circ_id) {

  streamcirc_t* sctx = streamcircmap_get(tlschan->streamcircmap, circ_id);

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC asked for streamcirc for circ_id %u, existing was %p, chan %p", circ_id, sctx, tlschan);
#endif

  if (!sctx) {

    if (!tlschan->peer) {
      // This means we're the listener side trying to write cells out,
      // but it appears we haven't received any QUIC streams from our client yet.
      // We can't connect back yet, so queue the cell until we can.
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC peer not arrived yet, circ_id %u cell will be queued for outbound, chan %p", circ_id, tlschan);
#endif
      return NULL;
    }

    if (circ_id == 0) {
      // no dynamic creation for the control stream,
      // that gets associated manually after the initial secret write
      log_debug(LD_CHANNEL, "ERROR BAD: QUIC attempted dynamic create of control stream!, chan %p", tlschan);

      // FIXME: there's a problem in that the initiator might not want to send
      // a cell on the control stream for some time, which would mean
      // the listener would have no way of knowing which is the control stream
      // if it wanted to send a cell.
      // Therefore we should either keep control cells going down TLS (probs not clever for traffic analysis),
      // or should indicate the control stream early, possibly using a padding cell.

      return NULL;
    }

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC creating a streamcirc for circ_id %u, chan %p", circ_id, tlschan);
#endif

    sctx = malloc(sizeof(streamcirc_t));
    sctx->tlschan = tlschan;
    sctx->stream = quux_connect(tlschan->peer);
    sctx->read_cell_pos = 0;
    sctx->write_cell_buf = buf_new();

    streamcircmap_set(tlschan->streamcircmap, circ_id, sctx);

    quux_set_readable_cb(sctx->stream, streamcirc_continue_read);
    quux_set_writeable_cb(sctx->stream, streamcirc_continue_write);
    quux_set_stream_context(sctx->stream, sctx);

    // kick the reader into action; should read nothing for the time being
    streamcirc_continue_read(sctx->stream);

    // XXX: NB: potentially consequential departure from the original protocol
    // in that previously once the OR->OR connection was set up, cell writes would
    // all be 512/514 bytes with the exception of var cells.
    // Now we also have that the initial send of a stream is a 32 byte secret.
    // I don't *think* this is an issue - the data cells are still opaque, the 32 bytes
    // should might still be resegmented onto another packet (?) and probably
    // if you squint hard enough the CREATE/CREATED pattern may be discernable already (?)
    //
    // The same applies to the control_stream secret, albeit that that is
    // very close to the TLS handshake, which is definitely observable.

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC about to send circuit TLS secret to circ %u streamcirc %p, chan %p", circ_id, sctx->stream, tlschan);
#endif
    // Write the secret along the stream to make sure the other end knows who we are.
    // If the write is incomplete then we'll cause the cell to be buffered.
    // We could be clever and only do this on the control_stream,
    // but it needs extra coding to be safe from race with the circuit streams.
    int secrets_write = streamcirc_attempt_write(sctx, tlschan->tlssecrets, DIGEST256_LEN);
    if (secrets_write < 0) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC not able to write TLS secret immediately, chan %p", tlschan);
#endif
      return NULL;
    }
  }

  return sctx;
}

static void streamcirc_associate_sctx(channel_tls_t *tlschan, circid_t circ_id, streamcirc_t* sctx) {

  // Called by the listener side, and by the client side for the control stream.
  // If the map entry existed it would mean something had gone very wrong,
  // with both sides trying to send an initial cell with same circid at the same time.
  // Should be impossible due to separated CircID spaces.
  // Or the other side is being malicious - I've ignored that case for now.
#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC associate streamcirc %u to %p, chan %p", circ_id, sctx, tlschan);
#endif
  streamcircmap_set(tlschan->streamcircmap, circ_id, sctx);
}

// An hmac using the tls master key. This is a sort of replay
// of the AUTHENTICATE cell sent over the wire, but since
// that should be confidential to just the TLS conn
// it should be safe to use again, provided the UDP stream is also confidential
//
// TODO: also want to delete entries once the connection goes away
tlssecretsmap_t* tlssecretsmap;

static void quic_closed_stream(quux_stream stream) {
  streamcirc_t* sctx = quux_get_stream_context(stream);
  quux_free_stream(stream);
  buf_free(sctx->write_cell_buf);
  free(sctx);
}

static void quic_accept_readable(quux_stream stream) {

  streamcirc_t* sctx = quux_get_stream_context(stream);

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC continuing with accept stream, sctx %p, chan %p", sctx, sctx->tlschan);
#endif

  if (!sctx->tlschan) {
    while (sctx->read_cell_pos < DIGEST256_LEN) {
      int bytes_read = quux_read(stream, sctx->read_cell_buf + sctx->read_cell_pos, DIGEST256_LEN - sctx->read_cell_pos);
      if (!bytes_read) {
#if QUUX_LOG
        log_debug(LD_CHANNEL, "QUIC paused during TLS secret read, sctx %p", sctx);
#endif
        return;
      }
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC partial TLS secret read, sctx %p", sctx);
#endif
      sctx->read_cell_pos += bytes_read;
    }

    /*
     * FIXME: possible timing oracle on the hash value could allow
     * an adversary to hijack an existing circuit or make their own for the chan
     * Possible mitigations:
     * 1) move the stream close into main's 1 second timer,
     * 2) ensure that all inbound streams must have the same secret as their control stream
     * The latter seems sufficient, and a good idea in any case.
     */
    channel_tls_t *tlschan = tlssecretsmap_get(tlssecretsmap, sctx->read_cell_buf);
    if (!tlschan) {
      char hex[2*DIGEST256_LEN+1];
      base16_encode(hex, 2*DIGEST256_LEN+1, (char*)sctx->read_cell_buf, DIGEST256_LEN);
      log_debug(LD_CHANNEL, "[err] QUIC got invalid auth secret %s, sctx %p", hex, sctx);

      if (quux_stream_status(stream) == 1) {
        quic_closed_stream(stream);
      } else {
        quux_set_closed_cb(stream, quic_closed_stream);
        quux_read_close(stream);
        quux_write_close(stream);
      }
      return;
    }

    // If tlschan is not in state OPEN then we've got a bit ahead of ourselves.
    // We should not read cells off the network until we go state OPEN
    if (!CHANNEL_IS_OPEN(TLS_CHAN_TO_BASE(tlschan))) {
      if (!tlschan->paused_circuits) {
        tlschan->paused_circuits = smartlist_new();
      }
      smartlist_add(tlschan->paused_circuits, stream);
      return;
    }

    sctx->tlschan = tlschan;

#if QUUX_LOG
    char hex[2*DIGEST256_LEN+1];
    base16_encode(hex, 2*DIGEST256_LEN+1, (char*)sctx->read_cell_buf, DIGEST256_LEN);
    log_debug(LD_CHANNEL, "QUIC valid auth secret %s, sctx %p, chan %p", hex, sctx, tlschan);
#endif

    sctx->read_cell_pos = 0;

    // For the listener-side - this would have been initialised to null in the TLS accept code
    // We pass through this code for each new inbound stream but only need to set it on the first
    if (!tlschan->peer) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC assigning the peer to its chan %p", tlschan);
#endif
      tlschan->peer = quux_get_peer(stream);
      if (tlschan->needs_flush) {
#if QUUX_LOG
        log_debug(LD_CHANNEL, "QUIC doing a flush of pending write cells, chan %p", tlschan);
#endif
        // This can happen if we tried to write cells out before the first QUIC stream arrived
        // in that case there would be no way to write the cells so they've been queued
        tlschan->needs_flush = 0;
        channel_flush_cells(TLS_CHAN_TO_BASE(sctx->tlschan));
      }
    }

    // continue reading the circ_id of the first cell, to identify the circuit
  }

  channel_tls_t *tlschan = sctx->tlschan;
  int wide_circ_ids = tlschan->conn->wide_circ_ids;
  int circ_id_size = get_circ_id_size(wide_circ_ids);

  while (sctx->read_cell_pos < circ_id_size) {
    int bytes_read = quux_read(stream, sctx->read_cell_buf + sctx->read_cell_pos, circ_id_size - sctx->read_cell_pos);
    if (!bytes_read) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "QUIC paused during circ_id read, chan %p", tlschan);
#endif
      return;
    }
    sctx->read_cell_pos += bytes_read;
  }

  // we've now read the first part of the first cell.
  // We'll leave read_cell_pos where it is, for the standard cell read code to fetch the rest
  circid_t circ_id;
  if (tlschan->conn->wide_circ_ids) {
    circ_id = net_get_uint32(sctx->read_cell_buf);
  } else {
    circ_id = net_get_uint16(sctx->read_cell_buf);
  }

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC got circ_id %d, chan %p", circ_id, tlschan);
#endif

  // now we have circ_id we can continue using the normal read cell logic
  quux_set_readable_cb(stream, streamcirc_continue_read);
  quux_set_writeable_cb(stream, streamcirc_continue_write);

  // Associate the stream to this circuit on the tlschan, so the write_cell code can find it
  streamcirc_associate_sctx(tlschan, circ_id, sctx);

  // continue with normal cell processing
  streamcirc_continue_read(stream);
}

/**
 * Used by both the connect and listen side as the starting point for accepting inbound streams.
 */
void quic_accept(quux_stream stream) {
  quux_set_readable_cb(stream, quic_accept_readable);

  streamcirc_t* sctx = malloc(sizeof(streamcirc_t));
  sctx->tlschan = NULL;
  sctx->stream = stream;
  sctx->read_cell_pos = 0;
  sctx->write_cell_buf = buf_new();

  quux_set_stream_context(stream, sctx);

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC stream accepted, sctx %p", sctx);
#endif

  // Start reading off the TLS secret
  quic_accept_readable(stream);
}

/**
 * Do parts of channel_tls_t initialization common to channel_tls_connect()
 * and channel_tls_handle_incoming().
 */

STATIC void
channel_tls_common_init(channel_tls_t *tlschan)
{
  channel_t *chan;

  tor_assert(tlschan);

  chan = &(tlschan->base_);
  channel_init(chan);
  chan->magic = TLS_CHAN_MAGIC;
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_tls_close_method;
  chan->describe_transport = channel_tls_describe_transport_method;
  chan->free = channel_tls_free_method;
  chan->get_overhead_estimate = channel_tls_get_overhead_estimate_method;
  chan->get_remote_addr = channel_tls_get_remote_addr_method;
  chan->get_remote_descr = channel_tls_get_remote_descr_method;
  chan->get_transport_name = channel_tls_get_transport_name_method;
  chan->has_queued_writes = channel_tls_has_queued_writes_method;
  chan->is_canonical = channel_tls_is_canonical_method;
  chan->matches_extend_info = channel_tls_matches_extend_info_method;
  chan->matches_target = channel_tls_matches_target_method;
  chan->num_bytes_queued = channel_tls_num_bytes_queued_method;
  chan->num_cells_writeable = channel_tls_num_cells_writeable_method;
  chan->write_cell = channel_tls_write_cell_method;
  chan->write_packed_cell = channel_tls_write_packed_cell_method;
  chan->write_var_cell = channel_tls_write_var_cell_method;

  chan->cmux = circuitmux_alloc();
  if (cell_ewma_enabled()) {
    circuitmux_set_policy(chan->cmux, &ewma_policy);
  }
}

/**
 * Start a new TLS channel
 *
 * Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>, and wrap
 * it in a channel_tls_t.
 */

channel_t *
channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest)
{
  channel_tls_t *tlschan = tor_malloc_zero(sizeof(*tlschan));
  channel_t *chan = &(tlschan->base_);

  channel_tls_common_init(tlschan);

  log_debug(LD_CHANNEL,
            "In channel_tls_connect() for channel %p "
            "(global id " U64_FORMAT ")",
            tlschan,
            U64_PRINTF_ARG(chan->global_identifier));

  if (is_local_addr(addr)) {
    log_debug(LD_CHANNEL,
              "Marking new outgoing channel " U64_FORMAT " at %p as local",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    channel_mark_local(chan);
  } else {
    log_debug(LD_CHANNEL,
              "Marking new outgoing channel " U64_FORMAT " at %p as remote",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    channel_mark_remote(chan);
  }

  channel_mark_outgoing(chan);

  /* Set up or_connection stuff */
  tlschan->conn = connection_or_connect(addr, port, id_digest, tlschan);
  /* connection_or_connect() will fill in tlschan->conn */
  if (!(tlschan->conn)) {
    chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
    channel_change_state(chan, CHANNEL_STATE_ERROR);
    goto err;
  }

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC connecting to peer");
#endif
  struct sockaddr_in6 sin;
  tor_addr_to_sockaddr(addr, port, (struct sockaddr*)&sin, sizeof(sin));

  tlschan->streamcircmap = streamcircmap_new();
  tlschan->peer = quux_open("example.com", (struct sockaddr*) &sin);
  quux_set_accept_cb(tlschan->peer, quic_accept);
#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC opened peer %p", tlschan->peer);
#endif

  // The purpose of this stream is to set the crypto handshake in motion.
  // Once both sides have completed TLS handshake we'll also use it to send the TLS secret asap.
  // After that point, the listener side will be able to connect back to us.
  streamcirc_t* sctx = malloc(sizeof(streamcirc_t));
  sctx->tlschan = tlschan;
  sctx->stream = quux_connect(tlschan->peer);
  sctx->read_cell_pos = 0;
  sctx->write_cell_buf = buf_new();

  // XXX: possible perf regression: we now do slow start twice,
  // once for TLS, then again on the quic conn

  tlschan->control_streamcirc = sctx;

#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC made control streamcirc, sctx %p", tlschan->control_streamcirc);
#endif
  quux_set_readable_cb(sctx->stream, streamcirc_continue_read);
  quux_set_writeable_cb(sctx->stream, streamcirc_continue_write);
  quux_set_stream_context(sctx->stream, sctx);

  // kick the reader into action; should read nothing for the time being
  streamcirc_continue_read(sctx->stream);

  log_debug(LD_CHANNEL,
            "Got orconn %p for channel with global id " U64_FORMAT,
            tlschan->conn, U64_PRINTF_ARG(chan->global_identifier));

  goto done;

 err:
  circuitmux_free(chan->cmux);
  tor_free(tlschan);
  chan = NULL;

 done:
  /* If we got one, we should register it */
  if (chan) channel_register(chan);

  return chan;
}

/**
 * Return the current channel_tls_t listener
 *
 * Returns the current channel listener for incoming TLS connections, or
 * NULL if none has been established
 */

channel_listener_t *
channel_tls_get_listener(void)
{
  return channel_tls_listener;
}

/**
 * Start a channel_tls_t listener if necessary
 *
 * Return the current channel_tls_t listener, or start one if we haven't yet,
 * and return that.
 */

channel_listener_t *
channel_tls_start_listener(void)
{
  channel_listener_t *listener;

  if (!channel_tls_listener) {
    listener = tor_malloc_zero(sizeof(*listener));
    channel_init_listener(listener);
    listener->state = CHANNEL_LISTENER_STATE_LISTENING;
    listener->close = channel_tls_listener_close_method;
    listener->describe_transport =
      channel_tls_listener_describe_transport_method;

    channel_tls_listener = listener;

    log_debug(LD_CHANNEL,
              "Starting TLS channel listener %p with global id " U64_FORMAT,
              listener, U64_PRINTF_ARG(listener->global_identifier));

    channel_listener_register(listener);
  } else listener = channel_tls_listener;

  return listener;
}

/**
 * Free everything on shutdown
 *
 * Not much to do here, since channel_free_all() takes care of a lot, but let's
 * get rid of the listener.
 */

void
channel_tls_free_all(void)
{
  channel_listener_t *old_listener = NULL;

  log_debug(LD_CHANNEL,
            "Shutting down TLS channels...");

  if (channel_tls_listener) {
    /*
     * When we close it, channel_tls_listener will get nulled out, so save
     * a pointer so we can free it.
     */
    old_listener = channel_tls_listener;
    log_debug(LD_CHANNEL,
              "Closing channel_tls_listener with ID " U64_FORMAT
              " at %p.",
              U64_PRINTF_ARG(old_listener->global_identifier),
              old_listener);
    channel_listener_unregister(old_listener);
    channel_listener_mark_for_close(old_listener);
    channel_listener_free(old_listener);
    tor_assert(channel_tls_listener == NULL);
  }

  log_debug(LD_CHANNEL,
            "Done shutting down TLS channels");
}

/**
 * Create a new channel around an incoming or_connection_t
 */

channel_t *
channel_tls_handle_incoming(or_connection_t *orconn)
{
  channel_tls_t *tlschan = tor_malloc_zero(sizeof(*tlschan));
  channel_t *chan = &(tlschan->base_);

  tor_assert(orconn);
  tor_assert(!(orconn->chan));

  channel_tls_common_init(tlschan);

  /* Link the channel and orconn to each other */
  tlschan->conn = orconn;
  orconn->chan = tlschan;
  tlschan->streamcircmap = streamcircmap_new();
  // Nb. tlschan->peer and others remain null at this point from malloc_zero

  if (is_local_addr(&(TO_CONN(orconn)->addr))) {
    log_debug(LD_CHANNEL,
              "Marking new incoming channel " U64_FORMAT " at %p as local",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    channel_mark_local(chan);
  } else {
    log_debug(LD_CHANNEL,
              "Marking new incoming channel " U64_FORMAT " at %p as remote",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    channel_mark_remote(chan);
  }

  channel_mark_incoming(chan);

  /* Register it */
  channel_register(chan);

  return chan;
}

/*********
 * Casts *
 ********/

/**
 * Cast a channel_tls_t to a channel_t.
 */

channel_t *
channel_tls_to_base(channel_tls_t *tlschan)
{
  if (!tlschan) return NULL;

  return &(tlschan->base_);
}

/**
 * Cast a channel_t to a channel_tls_t, with appropriate type-checking
 * asserts.
 */

channel_tls_t *
channel_tls_from_base(channel_t *chan)
{
  if (!chan) return NULL;

  tor_assert(chan->magic == TLS_CHAN_MAGIC);

  return (channel_tls_t *)(chan);
}

/********************************************
 * Method implementations for channel_tls_t *
 *******************************************/

/**
 * Close a channel_tls_t
 *
 * This implements the close method for channel_tls_t
 */

static void
channel_tls_close_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  if (tlschan->control_streamcirc) {
    quux_read_close(tlschan->control_streamcirc->stream);
    quux_write_close(tlschan->control_streamcirc->stream);
  }

  MAP_FOREACH(streamcircmap_, tlschan->streamcircmap, circid_t, k, streamcirc_t*, sctx) {
#if QUUX_LOG
  log_debug(LD_CHANNEL, "QUIC closing stream %d", k);
#endif
    quux_read_close(sctx->stream);
    quux_write_close(sctx->stream);
  } MAP_FOREACH_END;

  if (tlschan->paused_circuits) {
    SMARTLIST_FOREACH_BEGIN(tlschan->paused_circuits, quux_stream, stream) {
      quux_read_close(stream);
      quux_write_close(stream);
    } SMARTLIST_FOREACH_END(stream);
  }

  // TODO: close the peer
  if (tlschan->peer) {
    quux_set_accept_cb(tlschan->peer, NULL);
  }

  if (tlschan->conn) connection_or_close_normally(tlschan->conn, 1);
  else {
    /* Weird - we'll have to change the state ourselves, I guess */
    log_info(LD_CHANNEL,
             "Tried to close channel_tls_t %p with NULL conn",
             tlschan);
    channel_change_state(chan, CHANNEL_STATE_ERROR);
  }
}

/**
 * Describe the transport for a channel_tls_t
 *
 * This returns the string "TLS channel on connection <id>" to the upper
 * layer.
 */

static const char *
channel_tls_describe_transport_method(channel_t *chan)
{
  static char *buf = NULL;
  uint64_t id;
  channel_tls_t *tlschan;
  const char *rv = NULL;

  tor_assert(chan);

  tlschan = BASE_CHAN_TO_TLS(chan);

  if (tlschan->conn) {
    id = TO_CONN(tlschan->conn)->global_identifier;

    if (buf) tor_free(buf);
    tor_asprintf(&buf,
                 "TLS channel (connection " U64_FORMAT ")",
                 U64_PRINTF_ARG(id));

    rv = buf;
  } else {
    rv = "TLS channel (no connection)";
  }

  return rv;
}

/**
 * Free a channel_tls_t
 *
 * This is called by the generic channel layer when freeing a channel_tls_t;
 * this happens either on a channel which has already reached
 * CHANNEL_STATE_CLOSED or CHANNEL_STATE_ERROR from channel_run_cleanup() or
 * on shutdown from channel_free_all().  In the latter case we might still
 * have an orconn active (which connection_free_all() will get to later),
 * so we should null out its channel pointer now.
 */

static void
channel_tls_free_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

#if QUUX_LOG
    log_err(LD_CHANNEL, "QUIC free for tlschan %p", tlschan);
#endif

    tlssecretsmap_remove(tlssecretsmap, tlschan->tlssecrets);

    if (tlschan->control_streamcirc) {
      if (quux_stream_status(tlschan->control_streamcirc->stream) == 1) {
        quic_closed_stream(tlschan->control_streamcirc->stream);
      } else {
        quux_set_closed_cb(tlschan->control_streamcirc->stream, quic_closed_stream);
        quux_read_close(tlschan->control_streamcirc->stream);
        quux_write_close(tlschan->control_streamcirc->stream);
      }
      tlschan->control_streamcirc = NULL;
    }

  MAP_FOREACH(streamcircmap_, tlschan->streamcircmap, circid_t, k, streamcirc_t*, sctx) {
#if QUUX_LOG
    log_err(LD_CHANNEL, "QUIC closing stream for circ_id %u", k);
#endif
    if (quux_stream_status(sctx->stream) == 1) {
      quic_closed_stream(sctx->stream);
    } else {
      quux_set_closed_cb(sctx->stream, quic_closed_stream);
      quux_read_close(sctx->stream);
      quux_write_close(sctx->stream);
    }
  } MAP_FOREACH_END;

  streamcircmap_free(tlschan->streamcircmap, NULL);
  tlschan->streamcircmap = NULL;

  if (tlschan->paused_circuits) {
    SMARTLIST_FOREACH_BEGIN(tlschan->paused_circuits, quux_stream, stream) {
      if (quux_stream_status(stream) == 1) {
        quic_closed_stream(stream);
      } else {
        quux_set_closed_cb(stream, quic_closed_stream);
        quux_read_close(stream);
        quux_write_close(stream);
      }
    } SMARTLIST_FOREACH_END(stream);

    smartlist_free(tlschan->paused_circuits);
    tlschan->paused_circuits = NULL;
  }

  if (tlschan->peer) {
    quux_set_accept_cb(tlschan->peer, NULL);
    // XXX: This is an immediate close, won't wait for anything to finish
    // TODO: unfortunately this doesn't cancel alarms properly
    //quux_close(tlschan->peer);
    tlschan->peer = NULL;
  }

  if (tlschan->conn) {
    tlschan->conn->chan = NULL;
    tlschan->conn = NULL;
  }
}

/**
 * Get an estimate of the average TLS overhead for the upper layer
 */

static double
channel_tls_get_overhead_estimate_method(channel_t *chan)
{
  // quux doesn't provide this type of information.
  // It's not a very good idea in general.
  // Tor doesn't need to faff about with this crap -
  // its use-case works just fine without it - and it shouldn't.
  return 1.0f;
}

/**
 * Get the remote address of a channel_tls_t
 *
 * This implements the get_remote_addr method for channel_tls_t; copy the
 * remote endpoint of the channel to addr_out and return 1 (always
 * succeeds for this transport).
 */

static int
channel_tls_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out)
{
  int rv = 0;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(addr_out);

  if (tlschan->conn) {
    tor_addr_copy(addr_out, &(TO_CONN(tlschan->conn)->addr));
    rv = 1;
  } else tor_addr_make_unspec(addr_out);

  return rv;
}

/**
 * Get the name of the pluggable transport used by a channel_tls_t.
 *
 * This implements the get_transport_name for channel_tls_t. If the
 * channel uses a pluggable transport, copy its name to
 * <b>transport_out</b> and return 0. If the channel did not use a
 * pluggable transport, return -1. */

static int
channel_tls_get_transport_name_method(channel_t *chan, char **transport_out)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(transport_out);
  tor_assert(tlschan->conn);

  if (!tlschan->conn->ext_or_transport)
    return -1;

  *transport_out = tor_strdup(tlschan->conn->ext_or_transport);
  return 0;
}

/**
 * Get endpoint description of a channel_tls_t
 *
 * This implements the get_remote_descr method for channel_tls_t; it returns
 * a text description of the remote endpoint of the channel suitable for use
 * in log messages.  The req parameter is 0 for the canonical address or 1 for
 * the actual address seen.
 */

static const char *
channel_tls_get_remote_descr_method(channel_t *chan, int flags)
{
#define MAX_DESCR_LEN 32

  static char buf[MAX_DESCR_LEN + 1];
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  connection_t *conn;
  const char *answer = NULL;
  char *addr_str;

  tor_assert(tlschan);

  if (tlschan->conn) {
    conn = TO_CONN(tlschan->conn);
    switch (flags) {
      case 0:
        /* Canonical address with port*/
        tor_snprintf(buf, MAX_DESCR_LEN + 1,
                     "%s:%u", conn->address, conn->port);
        answer = buf;
        break;
      case GRD_FLAG_ORIGINAL:
        /* Actual address with port */
        addr_str = tor_dup_addr(&(tlschan->conn->real_addr));
        tor_snprintf(buf, MAX_DESCR_LEN + 1,
                     "%s:%u", addr_str, conn->port);
        tor_free(addr_str);
        answer = buf;
        break;
      case GRD_FLAG_ADDR_ONLY:
        /* Canonical address, no port */
        strlcpy(buf, conn->address, sizeof(buf));
        answer = buf;
        break;
      case GRD_FLAG_ORIGINAL|GRD_FLAG_ADDR_ONLY:
        /* Actual address, no port */
        addr_str = tor_dup_addr(&(tlschan->conn->real_addr));
        strlcpy(buf, addr_str, sizeof(buf));
        tor_free(addr_str);
        answer = buf;
        break;
      default:
        /* Something's broken in channel.c */
        tor_assert(1);
    }
  } else {
    strlcpy(buf, "(No connection)", sizeof(buf));
    answer = buf;
  }

  return answer;
}

/**
 * Tell the upper layer if we have queued writes
 *
 * This implements the has_queued_writes method for channel_tls t_; it returns
 * 1 iff we have queued writes on the outbuf of the underlying or_connection_t.
 *
 * For QUIC this doesn't make much sense without knowing a circuit ID
 * but 0 works fine as a default.
 */

static int
channel_tls_has_queued_writes_method(channel_t *chan)
{
  size_t outbuf_len;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called has_queued_writes on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
  }

  outbuf_len = (tlschan->conn != NULL) ?
    connection_get_outbuf_len(TO_CONN(tlschan->conn)) :
    0;

  return (outbuf_len > 0);
}

/**
 * Tell the upper layer if we're canonical
 *
 * This implements the is_canonical method for channel_tls_t; if req is zero,
 * it returns whether this is a canonical channel, and if it is one it returns
 * whether that can be relied upon.
 */

static int
channel_tls_is_canonical_method(channel_t *chan, int req)
{
  int answer = 0;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  if (tlschan->conn) {
    switch (req) {
      case 0:
        answer = tlschan->conn->is_canonical;
        break;
      case 1:
        /*
         * Is the is_canonical bit reliable?  In protocols version 2 and up
         * we get the canonical address from a NETINFO cell, but in older
         * versions it might be based on an obsolete descriptor.
         */
        answer = (tlschan->conn->link_proto >= 2);
        break;
      default:
        /* This shouldn't happen; channel.c is broken if it does */
        tor_assert(1);
    }
  }
  /* else return 0 for tlschan->conn == NULL */

  return answer;
}

/**
 * Check if we match an extend_info_t
 *
 * This implements the matches_extend_info method for channel_tls_t; the upper
 * layer wants to know if this channel matches an extend_info_t.
 */

static int
channel_tls_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(extend_info);

  /* Never match if we have no conn */
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called matches_extend_info on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
    return 0;
  }

  return (tor_addr_eq(&(extend_info->addr),
                      &(TO_CONN(tlschan->conn)->addr)) &&
         (extend_info->port == TO_CONN(tlschan->conn)->port));
}

/**
 * Check if we match a target address; return true iff we do.
 *
 * This implements the matches_target method for channel_tls t_; the upper
 * layer wants to know if this channel matches a target address when extending
 * a circuit.
 */

static int
channel_tls_matches_target_method(channel_t *chan,
                                  const tor_addr_t *target)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(target);

  /* Never match if we have no conn */
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called matches_target on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
    return 0;
  }

  return tor_addr_eq(&(tlschan->conn->real_addr), target);
}

/**
 * Tell the upper layer how many bytes we have queued and not yet
 * sent.
 *
 * For QUIC this doesn't make much sense without knowing a circuit ID
 * but 0 works fine as a default.
 */

static size_t
channel_tls_num_bytes_queued_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(tlschan->conn);

  return connection_get_outbuf_len(TO_CONN(tlschan->conn));
}

/**
 * Tell the upper layer how many cells we can accept to write
 *
 * This implements the num_cells_writeable method for channel_tls_t; it
 * returns an estimate of the number of cells we can accept with
 * channel_tls_write_*_cell().
 */

/**
 * This abstraction is most unfortunate firstly because it's not specific to any circuit,
 * secondly because it implies that we must have another whopping queue area after
 * the p/n_queue.
 *
 * At least for the former reason, we'll say always writeable at this point
 * and fix the scheduler to be less surprised about not writing everything
 */
static int
channel_tls_num_cells_writeable_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  size_t cell_network_size = get_cell_network_size(tlschan->conn->wide_circ_ids);
  return CEIL_DIV(OR_CONN_HIGHWATER, cell_network_size);
}

/**
 * Write a cell to a channel_tls_t
 *
 * This implements the write_cell method for channel_tls_t; given a
 * channel_tls_t and a cell_t, transmit the cell_t.
 */

int
channel_tls_write_cell_method(channel_t *chan, cell_t *cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  int written = 0;

  tor_assert(tlschan);
  tor_assert(cell);

  if (tlschan->conn) {
    packed_cell_t networkcell;
    size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);

    streamcirc_t* sctx = channel_tls_get_streamcirc(tlschan, cell->circ_id);
    if (!sctx) {
      tlschan->needs_flush = 1;
      return 0;
    }

    cell_pack(&networkcell, cell, tlschan->conn->wide_circ_ids);

    int css = maybe_get_cs_shift(tlschan, cell->circ_id);
    int wrote = streamcirc_attempt_write(sctx, (uint8_t*)networkcell.body+css, cell_network_size-css);

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC asked to write %s cell %lu bytes, status %d, chan %p", cell_command_to_string(cell->command), cell_network_size, wrote, chan);
#endif
    if (wrote < 0) {
      return 0;
    }
    maybe_clear_cs_shift(tlschan, cell->circ_id);

    // By the function comment it sounds like this only relates to standard conns
#if 0
    /* Touch the channel's active timestamp if there is one */
    if (tlschan->conn->chan)
      channel_timestamp_active(TLS_CHAN_TO_BASE(tlschan->conn->chan));
#endif

    ++written;
  } else {
    log_info(LD_CHANNEL,
             "something called write_cell on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
  }

  return written;
}

/**
 * Write a packed cell to a channel_tls_t
 *
 * This implements the write_packed_cell method for channel_tls_t; given a
 * channel_tls_t and a packed_cell_t, transmit the packed_cell_t.
 */

static int
channel_tls_write_packed_cell_method(channel_t *chan,
                                     packed_cell_t *packed_cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  int written = 0;

  tor_assert(tlschan);
  tor_assert(packed_cell);

  if (tlschan->conn) {
    circid_t circ_id;
    if (tlschan->conn->wide_circ_ids) {
      circ_id = net_get_uint32((uint8_t*)packed_cell->body);
    } else {
      circ_id = net_get_uint16((uint8_t*)packed_cell->body);
    }

    streamcirc_t* sctx = channel_tls_get_streamcirc(tlschan, circ_id);
    if (!sctx) {
#if QUUX_LOG
      log_debug(LD_CHANNEL, "There was no sctx");
#endif
      tlschan->needs_flush = 1;
      return 0;
    }

#if QUUX_LOG
    log_debug(LD_CHANNEL, "About to write %zu", cell_network_size);
#endif

    int css = maybe_get_cs_shift(tlschan, circ_id);
    int wrote = streamcirc_attempt_write(sctx, (uint8_t*)packed_cell->body+css, cell_network_size-css);

#if QUUX_LOG
    int cell_command = packed_cell->body[get_circ_id_size(tlschan->conn->wide_circ_ids)];
    log_debug(LD_CHANNEL, "QUIC asked to write circuit %u packed %s cell QUIC %lu bytes, status %d, chan %p",
        circ_id, cell_command_to_string(cell_command), cell_network_size, wrote, chan);
#endif

    if (wrote < 0) {
      return 0;
    }

    maybe_clear_cs_shift(tlschan, circ_id);

    /* This is where the cell is finished; used to be done from relay.c */
    packed_cell_free(packed_cell);
    ++written;
  } else {
    log_info(LD_CHANNEL,
             "something called write_packed_cell on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
  }

  return written;
}

/**
 * Write a variable-length cell to a channel_tls_t
 *
 * This implements the write_var_cell method for channel_tls_t; given a
 * channel_tls_t and a var_cell_t, transmit the var_cell_t.
 */

static int
channel_tls_write_var_cell_method(channel_t *chan, var_cell_t *var_cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  int written = 0;

  tor_assert(tlschan);
  tor_assert(var_cell);

  if (tlschan->conn) {
    streamcirc_t* sctx = channel_tls_get_streamcirc(tlschan, var_cell->circ_id);
    if (!sctx) {
      tlschan->needs_flush = 1;
      return 0;
    }

    uint8_t buf[CELL_MAX_NETWORK_SIZE];
    int n = var_cell_pack_header(var_cell, (char*)buf, tlschan->conn->wide_circ_ids);
    int total_len = (unsigned long)n + var_cell->payload_len;

    if (total_len > CELL_MAX_NETWORK_SIZE) {
      // Not supported yet
      tor_assert(0);
    }

    // using an extra buf because 'streamcirc_attempt_write' only
    // supports one write attempt per cell, so we use contiguous memory.
    // could change it to use an iovec array but meh
    memcpy(buf + n, var_cell->payload, var_cell->payload_len);

    int css = maybe_get_cs_shift(tlschan, var_cell->circ_id);
    int wrote = streamcirc_attempt_write(sctx, buf+css, total_len-css);

#if QUUX_LOG
    log_debug(LD_CHANNEL, "QUIC Asked to write %s var cell %d bytes, status %d, chan %p", cell_command_to_string(var_cell->command), total_len, wrote, chan);
#endif

    if (wrote < 0) {
      return 0;
    }

    maybe_clear_cs_shift(tlschan, var_cell->circ_id);

    // By the function comment it sounds like this only relates to standard conns
#if 0
    /* Touch the channel's active timestamp if there is one */
    if (tlschan->conn->chan)
      channel_timestamp_active(TLS_CHAN_TO_BASE(tlschan->conn->chan));
#endif
    ++written;
  } else {
    log_info(LD_CHANNEL,
             "something called write_var_cell on a tlschan "
             "(%p with ID " U64_FORMAT " but no conn",
             chan, U64_PRINTF_ARG(chan->global_identifier));
  }

  return written;
}

/*************************************************
 * Method implementations for channel_listener_t *
 ************************************************/

/**
 * Close a channel_listener_t
 *
 * This implements the close method for channel_listener_t
 */

static void
channel_tls_listener_close_method(channel_listener_t *chan_l)
{
  tor_assert(chan_l);

  /*
   * Listeners we just go ahead and change state through to CLOSED, but
   * make sure to check if they're channel_tls_listener to NULL it out.
   */
  if (chan_l == channel_tls_listener)
    channel_tls_listener = NULL;

  if (!(chan_l->state == CHANNEL_LISTENER_STATE_CLOSING ||
        chan_l->state == CHANNEL_LISTENER_STATE_CLOSED ||
        chan_l->state == CHANNEL_LISTENER_STATE_ERROR)) {
    channel_listener_change_state(chan_l, CHANNEL_LISTENER_STATE_CLOSING);
  }

  if (chan_l->incoming_list) {
    SMARTLIST_FOREACH_BEGIN(chan_l->incoming_list,
                            channel_t *, ichan) {
      channel_mark_for_close(ichan);
    } SMARTLIST_FOREACH_END(ichan);

    smartlist_free(chan_l->incoming_list);
    chan_l->incoming_list = NULL;
  }

  if (!(chan_l->state == CHANNEL_LISTENER_STATE_CLOSED ||
        chan_l->state == CHANNEL_LISTENER_STATE_ERROR)) {
    channel_listener_change_state(chan_l, CHANNEL_LISTENER_STATE_CLOSED);
  }
}

/**
 * Describe the transport for a channel_listener_t
 *
 * This returns the string "TLS channel (listening)" to the upper
 * layer.
 */

static const char *
channel_tls_listener_describe_transport_method(channel_listener_t *chan_l)
{
  tor_assert(chan_l);

  return "TLS channel (listening)";
}

/*******************************************************
 * Functions for handling events on an or_connection_t *
 ******************************************************/

/**
 * Handle an orconn state change
 *
 * This function will be called by connection_or.c when the or_connection_t
 * associated with this channel_tls_t changes state.
 */

void
channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                          or_connection_t *conn,
                                          uint8_t old_state,
                                          uint8_t state)
{
  channel_t *base_chan;

  tor_assert(chan);
  tor_assert(conn);
  tor_assert(conn->chan == chan);
  tor_assert(chan->conn == conn);
  /* Shut the compiler up without triggering -Wtautological-compare */
  (void)old_state;

  base_chan = TLS_CHAN_TO_BASE(chan);

  /* Make sure the base connection state makes sense - shouldn't be error
   * or closed. */

  tor_assert(CHANNEL_IS_OPENING(base_chan) ||
             CHANNEL_IS_OPEN(base_chan) ||
             CHANNEL_IS_MAINT(base_chan) ||
             CHANNEL_IS_CLOSING(base_chan));

  /* Did we just go to state open? */
  if (state == OR_CONN_STATE_OPEN) {
    /*
     * We can go to CHANNEL_STATE_OPEN from CHANNEL_STATE_OPENING or
     * CHANNEL_STATE_MAINT on this.
     */
    channel_change_state(base_chan, CHANNEL_STATE_OPEN);

    // At this point we've received a VERSIONS cell,
    // which means the other side has definitially finished the handshake, as have we
    streamcirc_t* sctx = chan->control_streamcirc;
    if (sctx) {
#if QUUX_LOG
      char hex[2*DIGEST256_LEN+1];
      base16_encode(hex, 2*DIGEST256_LEN+1, (char*)chan->tlssecrets, DIGEST256_LEN);
      log_debug(LD_CHANNEL, "QUIC sending auth secret %s for, chan %p", hex, chan);
#endif

      // streamcirc_attempt_write works in single block writes, so need to join the two items
      uint8_t control_buf[DIGEST256_LEN+sizeof(circid_t)];
      int circ_id_size = get_circ_id_size(conn->wide_circ_ids);
      memcpy(control_buf, chan->tlssecrets, DIGEST256_LEN);
      // We need to write circ_id early, otherwise the listener will have
      // no recourse for sending cells on the control stream until we have done.
      // We could have sent a padding cell, just that it's a bit wasteful of bw.
      memset(control_buf+DIGEST256_LEN, 0, circ_id_size);

      streamcirc_attempt_write(sctx, control_buf, DIGEST256_LEN+circ_id_size);

      // Now the TLS secret is written we can register the stream as CircID 0
      streamcirc_associate_sctx(chan, 0, sctx);
      chan->control_streamcirc = NULL;
      chan->buffered_cs_id = 1;

    } else {
      // the client goes OPEN before the listener, so may already have had circuits too early
      if (chan->paused_circuits) {
        SMARTLIST_FOREACH(chan->paused_circuits, quux_stream, stream,
            quic_accept_readable(stream));
        smartlist_free(chan->paused_circuits);
        chan->paused_circuits = NULL;
      }
    }

    /* We might have just become writeable; check and tell the scheduler */
    if (connection_or_num_cells_writeable(conn) > 0) {
      scheduler_channel_wants_writes(base_chan);
    }
  } else {
    /*
     * Not open, so from CHANNEL_STATE_OPEN we go to CHANNEL_STATE_MAINT,
     * otherwise no change.
     */
    if (CHANNEL_IS_OPEN(base_chan)) {
      channel_change_state(base_chan, CHANNEL_STATE_MAINT);
    }
  }
}

#ifdef KEEP_TIMING_STATS

/**
 * Timing states wrapper
 *
 * This is a wrapper function around the actual function that processes the
 * <b>cell</b> that just arrived on <b>chan</b>. Increment <b>*time</b>
 * by the number of microseconds used by the call to <b>*func(cell, chan)</b>.
 */

static void
channel_tls_time_process_cell(cell_t *cell, channel_tls_t *chan, int *time,
                              void (*func)(cell_t *, channel_tls_t *))
{
  struct timeval start, end;
  long time_passed;

  tor_gettimeofday(&start);

  (*func)(cell, chan);

  tor_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 10000) { /* more than 10ms */
    log_debug(LD_OR,"That call just took %ld ms.",time_passed/1000);
  }

  if (time_passed < 0) {
    log_info(LD_GENERAL,"That call took us back in time!");
    time_passed = 0;
  }

  *time += time_passed;
}
#endif

/**
 * Handle an incoming cell on a channel_tls_t
 *
 * This is called from connection_or.c to handle an arriving cell; it checks
 * for cell types specific to the handshake for this transport protocol and
 * handles them, and queues all other cells to the channel_t layer, which
 * eventually will hand them off to command.c.
 */

void
channel_tls_handle_cell(cell_t *cell, or_connection_t *conn)
{
  channel_tls_t *chan;
  int handshaking;

#ifdef KEEP_TIMING_STATS
#define PROCESS_CELL(tp, cl, cn) STMT_BEGIN {                   \
    ++num ## tp;                                                \
    channel_tls_time_process_cell(cl, cn, & tp ## time ,            \
                             channel_tls_process_ ## tp ## _cell);  \
    } STMT_END
#else
#define PROCESS_CELL(tp, cl, cn) channel_tls_process_ ## tp ## _cell(cl, cn)
#endif

  tor_assert(cell);
  tor_assert(conn);

  chan = conn->chan;

 if (!chan) {
   log_warn(LD_CHANNEL,
            "Got a cell_t on an OR connection with no channel");
   return;
  }

  handshaking = (TO_CONN(conn)->state != OR_CONN_STATE_OPEN);

  if (conn->base_.marked_for_close)
    return;

  /* Reject all but VERSIONS and NETINFO when handshaking. */
  /* (VERSIONS should actually be impossible; it's variable-length.) */
  if (handshaking && cell->command != CELL_VERSIONS &&
      cell->command != CELL_NETINFO) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received unexpected cell command %d in chan state %s / "
           "conn state %s; closing the connection.",
           (int)cell->command,
           channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
           conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state));
    connection_or_close_for_error(conn, 0);
    return;
  }

  if (conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3)
    or_handshake_state_record_cell(conn, conn->handshake_state, cell, 1);

  log_debug(LD_PROTOCOL, "Received a cell with command %s on chan %p",
            cell_command_to_string(cell->command), chan);

  switch (cell->command) {
    case CELL_PADDING:
      ++stats_n_padding_cells_processed;
      /* do nothing */
      break;
    case CELL_VERSIONS:
      tor_fragile_assert();
      break;
    case CELL_NETINFO:
      ++stats_n_netinfo_cells_processed;
      PROCESS_CELL(netinfo, cell, chan);
      break;
    case CELL_CREATE:
    case CELL_CREATE_FAST:
    case CELL_CREATED:
    case CELL_CREATED_FAST:
    case CELL_RELAY:
    case CELL_RELAY_EARLY:
    case CELL_DESTROY:
    case CELL_CREATE2:
    case CELL_CREATED2:
      /*
       * These are all transport independent and we pass them up through the
       * channel_t mechanism.  They are ultimately handled in command.c.
       */
      channel_queue_cell(TLS_CHAN_TO_BASE(chan), cell);
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Cell of unknown type (%d) received in channeltls.c.  "
             "Dropping.",
             cell->command);
             break;
  }
}

/**
 * Handle an incoming variable-length cell on a channel_tls_t
 *
 * Process a <b>var_cell</b> that was just received on <b>conn</b>. Keep
 * internal statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.  All the var_cell commands are handshake-
 * related and live below the channel_t layer, so no variable-length
 * cells ever get delivered in the current implementation, but I've left
 * the mechanism in place for future use.
 */

void
channel_tls_handle_var_cell(var_cell_t *var_cell, or_connection_t *conn)
{
  channel_tls_t *chan;

#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_versions = 0, num_certs = 0;
  static time_t current_second = 0; /* from previous calls to time */
  time_t now = time(NULL);

  if (current_second == 0) current_second = now;
  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,
             "At end of second: %d versions (%d ms), %d certs (%d ms)",
             num_versions, versions_time / ((now - current_second) * 1000),
             num_certs, certs_time / ((now - current_second) * 1000));

    num_versions = num_certs = 0;
    versions_time = certs_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

  tor_assert(var_cell);
  tor_assert(conn);

  chan = conn->chan;

  if (!chan) {
    log_warn(LD_CHANNEL,
             "Got a var_cell_t on an OR connection with no channel");
    return;
  }

  if (TO_CONN(conn)->marked_for_close)
    return;

  log_debug(LD_PROTOCOL, "Received a var cell with command %s on chan %p",
            cell_command_to_string(var_cell->command), chan);

  switch (TO_CONN(conn)->state) {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
      if (var_cell->command != CELL_VERSIONS) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in unexpected "
               "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
               "closing the connection.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               TO_CONN(conn)->state,
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state));
        /*
         * The code in connection_or.c will tell channel_t to close for
         * error; it will go to CHANNEL_STATE_CLOSING, and then to
         * CHANNEL_STATE_ERROR when conn is closed.
         */
        connection_or_close_for_error(conn, 0);
        return;
      }
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
      /* If we're using bufferevents, it's entirely possible for us to
       * notice "hey, data arrived!" before we notice "hey, the handshake
       * finished!" And we need to be accepting both at once to handle both
       * the v2 and v3 handshakes. */

      /* fall through */
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
      if (!(command_allowed_before_handshake(var_cell->command))) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in unexpected "
               "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
               "closing the connection.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               (int)(TO_CONN(conn)->state),
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state));
        /* see above comment about CHANNEL_STATE_ERROR */
        connection_or_close_for_error(conn, 0);
        return;
      } else {
        if (enter_v3_handshake_with_cell(var_cell, chan) < 0)
          return;
      }
      break;
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      if (var_cell->command != CELL_AUTHENTICATE)
        or_handshake_state_record_var_cell(conn, conn->handshake_state,
                                           var_cell, 1);
      break; /* Everything is allowed */
    case OR_CONN_STATE_OPEN:
      if (conn->link_proto < 3) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a variable-length cell with command %d in orconn "
               "state %s [%d], channel state %s [%d] with link protocol %d; "
               "ignoring it.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               (int)(TO_CONN(conn)->state),
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state),
               (int)(conn->link_proto));
        return;
      }
      break;
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Received var-length cell with command %d in unexpected "
             "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
             "ignoring it.",
             (int)(var_cell->command),
             conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
             (int)(TO_CONN(conn)->state),
             channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
             (int)(TLS_CHAN_TO_BASE(chan)->state));
      return;
  }

  /* Now handle the cell */

  switch (var_cell->command) {
    case CELL_VERSIONS:
      ++stats_n_versions_cells_processed;
      PROCESS_CELL(versions, var_cell, chan);
      break;
    case CELL_VPADDING:
      ++stats_n_vpadding_cells_processed;
      /* Do nothing */
      break;
    case CELL_CERTS:
      ++stats_n_certs_cells_processed;
      PROCESS_CELL(certs, var_cell, chan);
      break;
    case CELL_AUTH_CHALLENGE:
      ++stats_n_auth_challenge_cells_processed;
      PROCESS_CELL(auth_challenge, var_cell, chan);
      break;
    case CELL_AUTHENTICATE:
      ++stats_n_authenticate_cells_processed;
      PROCESS_CELL(authenticate, var_cell, chan);
      break;
    case CELL_AUTHORIZE:
      ++stats_n_authorize_cells_processed;
      /* Ignored so far. */
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Variable-length cell of unknown type (%d) received.",
             (int)(var_cell->command));
      break;
  }
}

/**
 * Update channel marks after connection_or.c has changed an address
 *
 * This is called from connection_or_init_conn_from_address() after the
 * connection's _base.addr or real_addr fields have potentially been changed
 * so we can recalculate the local mark.  Notably, this happens when incoming
 * connections are reverse-proxied and we only learn the real address of the
 * remote router by looking it up in the consensus after we finish the
 * handshake and know an authenticated identity digest.
 */

void
channel_tls_update_marks(or_connection_t *conn)
{
  channel_t *chan = NULL;

  tor_assert(conn);
  tor_assert(conn->chan);

  chan = TLS_CHAN_TO_BASE(conn->chan);

  if (is_local_addr(&(TO_CONN(conn)->addr))) {
    if (!channel_is_local(chan)) {
      log_debug(LD_CHANNEL,
                "Marking channel " U64_FORMAT " at %p as local",
                U64_PRINTF_ARG(chan->global_identifier), chan);
      channel_mark_local(chan);
    }
  } else {
    if (channel_is_local(chan)) {
      log_debug(LD_CHANNEL,
                "Marking channel " U64_FORMAT " at %p as remote",
                U64_PRINTF_ARG(chan->global_identifier), chan);
      channel_mark_remote(chan);
    }
  }
}

/**
 * Check if this cell type is allowed before the handshake is finished
 *
 * Return true if <b>command</b> is a cell command that's allowed to start a
 * V3 handshake.
 */

static int
command_allowed_before_handshake(uint8_t command)
{
  switch (command) {
    case CELL_VERSIONS:
    case CELL_VPADDING:
    case CELL_AUTHORIZE:
      return 1;
    default:
      return 0;
  }
}

/**
 * Start a V3 handshake on an incoming connection
 *
 * Called when we as a server receive an appropriate cell while waiting
 * either for a cell or a TLS handshake.  Set the connection's state to
 * "handshaking_v3', initializes the or_handshake_state field as needed,
 * and add the cell to the hash of incoming cells.)
 */

static int
enter_v3_handshake_with_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int started_here = 0;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  started_here = connection_or_nonopen_was_started_here(chan->conn);

  tor_assert(TO_CONN(chan->conn)->state == OR_CONN_STATE_TLS_HANDSHAKING ||
             TO_CONN(chan->conn)->state ==
               OR_CONN_STATE_TLS_SERVER_RENEGOTIATING);

  if (started_here) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a cell while TLS-handshaking, not in "
           "OR_HANDSHAKING_V3, on a connection we originated.");
  }
  connection_or_block_renegotiation(chan->conn);
  chan->conn->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  if (connection_init_or_handshake_state(chan->conn, started_here) < 0) {
    connection_or_close_for_error(chan->conn, 0);
    return -1;
  }
  or_handshake_state_record_var_cell(chan->conn,
                                     chan->conn->handshake_state, cell, 1);
  return 0;
}

/**
 * Process a 'versions' cell.
 *
 * This function is called to handle an incoming VERSIONS cell; the current
 * link protocol version must be 0 to indicate that no version has yet been
 * negotiated.  We compare the versions in the cell to the list of versions
 * we support, pick the highest version we have in common, and continue the
 * negotiation from there.
 */

static void
channel_tls_process_versions_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int highest_supported_version = 0;
  int started_here = 0;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  if ((cell->payload_len % 2) == 1) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSION cell with odd payload length %d; "
           "closing connection.",cell->payload_len);
    connection_or_close_for_error(chan->conn, 0);
    return;
  }

  started_here = connection_or_nonopen_was_started_here(chan->conn);

  if (chan->conn->link_proto != 0 ||
      (chan->conn->handshake_state &&
       chan->conn->handshake_state->received_versions)) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSIONS cell on a connection with its version "
           "already set to %d; dropping",
           (int)(chan->conn->link_proto));
    return;
  }
  switch (chan->conn->base_.state)
    {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "VERSIONS cell while in unexpected state");
      return;
  }

  tor_assert(chan->conn->handshake_state);

  {
    int i;
    const uint8_t *cp = cell->payload;
    for (i = 0; i < cell->payload_len / 2; ++i, cp += 2) {
      uint16_t v = ntohs(get_uint16(cp));
      if (is_or_protocol_version_known(v) && v > highest_supported_version)
        highest_supported_version = v;
    }
  }
  if (!highest_supported_version) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Couldn't find a version in common between my version list and the "
           "list in the VERSIONS cell; closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version == 1) {
    /* Negotiating version 1 makes no sense, since version 1 has no VERSIONS
     * cells. */
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Used version negotiation protocol to negotiate a v1 connection. "
           "That's crazily non-compliant. Closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version < 3 &&
             chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Negotiated link protocol 2 or lower after doing a v3 TLS "
           "handshake. Closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version != 2 &&
             chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V2) {
    /* XXXX This should eventually be a log_protocol_warn */
    log_fn(LOG_WARN, LD_OR,
           "Negotiated link with non-2 protocol after doing a v2 TLS "
           "handshake with %s. Closing connection.",
           fmt_addr(&chan->conn->base_.addr));
    connection_or_close_for_error(chan->conn, 0);
    return;
  }

  rep_hist_note_negotiated_link_proto(highest_supported_version, started_here);

  chan->conn->link_proto = highest_supported_version;
  chan->conn->handshake_state->received_versions = 1;

  if (chan->conn->link_proto == 2) {
    log_info(LD_OR,
             "Negotiated version %d with %s:%d; sending NETINFO.",
             highest_supported_version,
             safe_str_client(chan->conn->base_.address),
             chan->conn->base_.port);

    if (connection_or_send_netinfo(chan->conn) < 0) {
      connection_or_close_for_error(chan->conn, 0);
      return;
    }
  } else {
    const int send_versions = !started_here;
    /* If we want to authenticate, send a CERTS cell */
    const int send_certs = !started_here || public_server_mode(get_options());
    /* If we're a host that got a connection, ask for authentication. */
    const int send_chall = !started_here;
    /* If our certs cell will authenticate us, we can send a netinfo cell
     * right now. */
    const int send_netinfo = !started_here;
    const int send_any =
      send_versions || send_certs || send_chall || send_netinfo;
    tor_assert(chan->conn->link_proto >= 3);

    log_info(LD_OR,
             "Negotiated version %d with %s:%d; %s%s%s%s%s",
             highest_supported_version,
             safe_str_client(chan->conn->base_.address),
             chan->conn->base_.port,
             send_any ? "Sending cells:" : "Waiting for CERTS cell",
             send_versions ? " VERSIONS" : "",
             send_certs ? " CERTS" : "",
             send_chall ? " AUTH_CHALLENGE" : "",
             send_netinfo ? " NETINFO" : "");

#ifdef DISABLE_V3_LINKPROTO_SERVERSIDE
    if (1) {
      connection_or_close_normally(chan->conn, 1);
      return;
    }
#endif

    // Now that (re)negotiation is complete, associate the channel
    // with a shared secret based on the master key
    // afaik, this is the first place we can be sure the listener has finished TLS handshake.
    master_key_digest(chan->conn->tls, chan->tlssecrets);
    tlssecretsmap_set(tlssecretsmap, chan->tlssecrets, chan);

#if QUUX_LOG
    char hex[2*DIGEST256_LEN+1];
    base16_encode(hex, 2*DIGEST256_LEN+1, (char*)chan->tlssecrets, DIGEST256_LEN);
    log_debug(LD_CHANNEL, "QUIC got versions auth secret %s, chan %p", hex, chan);
#endif

    if (send_versions) {
      if (connection_or_send_versions(chan->conn, 1) < 0) {
        log_warn(LD_OR, "Couldn't send versions cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }

    /* We set this after sending the verions cell. */
    /*XXXXX symbolic const.*/
    chan->base_.wide_circ_ids =
      chan->conn->link_proto >= MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS;
    chan->conn->wide_circ_ids = chan->base_.wide_circ_ids;

    if (send_certs) {
      if (connection_or_send_certs_cell(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send certs cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
    if (send_chall) {
      if (connection_or_send_auth_challenge_cell(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send auth_challenge cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
    if (send_netinfo) {
      if (connection_or_send_netinfo(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send netinfo cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
  }
}

/**
 * Process a 'netinfo' cell
 *
 * This function is called to handle an incoming NETINFO cell; read and act
 * on its contents, and set the connection state to "open".
 */

static void
channel_tls_process_netinfo_cell(cell_t *cell, channel_tls_t *chan)
{
  time_t timestamp;
  uint8_t my_addr_type;
  uint8_t my_addr_len;
  const uint8_t *my_addr_ptr;
  const uint8_t *cp, *end;
  uint8_t n_other_addrs;
  time_t now = time(NULL);

  long apparent_skew = 0;
  tor_addr_t my_apparent_addr = TOR_ADDR_NULL;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  if (chan->conn->link_proto < 2) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on %s connection; dropping.",
           chan->conn->link_proto == 0 ? "non-versioned" : "a v1");
    return;
  }
  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V2 &&
      chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on non-handshaking connection; dropping.");
    return;
  }
  tor_assert(chan->conn->handshake_state &&
             chan->conn->handshake_state->received_versions);

  if (chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3) {
    tor_assert(chan->conn->link_proto >= 3);
    if (chan->conn->handshake_state->started_here) {
      if (!(chan->conn->handshake_state->authenticated)) {
        log_fn(LOG_PROTOCOL_WARN, LD_OR,
               "Got a NETINFO cell from server, "
               "but no authentication.  Closing the connection.");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    } else {
      /* we're the server.  If the client never authenticated, we have
         some housekeeping to do.*/
      if (!(chan->conn->handshake_state->authenticated)) {
        tor_assert(tor_digest_is_zero(
                  (const char*)(chan->conn->handshake_state->
                      authenticated_peer_id)));
        channel_set_circid_type(TLS_CHAN_TO_BASE(chan), NULL,
               chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);

        connection_or_init_conn_from_address(chan->conn,
                  &(chan->conn->base_.addr),
                  chan->conn->base_.port,
                  (const char*)(chan->conn->handshake_state->
                   authenticated_peer_id),
                  0);
      }
    }
  }

  /* Decode the cell. */
  timestamp = ntohl(get_uint32(cell->payload));
  if (labs(now - chan->conn->handshake_state->sent_versions_at) < 180) {
    apparent_skew = now - timestamp;
  }

  my_addr_type = (uint8_t) cell->payload[4];
  my_addr_len = (uint8_t) cell->payload[5];
  my_addr_ptr = (uint8_t*) cell->payload + 6;
  end = cell->payload + CELL_PAYLOAD_SIZE;
  cp = cell->payload + 6 + my_addr_len;

  /* We used to check:
   *    if (my_addr_len >= CELL_PAYLOAD_SIZE - 6) {
   *
   * This is actually never going to happen, since my_addr_len is at most 255,
   * and CELL_PAYLOAD_LEN - 6 is 503.  So we know that cp is < end. */

  if (my_addr_type == RESOLVED_TYPE_IPV4 && my_addr_len == 4) {
    tor_addr_from_ipv4n(&my_apparent_addr, get_uint32(my_addr_ptr));
  } else if (my_addr_type == RESOLVED_TYPE_IPV6 && my_addr_len == 16) {
    tor_addr_from_ipv6_bytes(&my_apparent_addr, (const char *) my_addr_ptr);
  }

  n_other_addrs = (uint8_t) *cp++;
  while (n_other_addrs && cp < end-2) {
    /* Consider all the other addresses; if any matches, this connection is
     * "canonical." */
    tor_addr_t addr;
    const uint8_t *next =
      decode_address_from_payload(&addr, cp, (int)(end-cp));
    if (next == NULL) {
      log_fn(LOG_PROTOCOL_WARN,  LD_OR,
             "Bad address in netinfo cell; closing connection.");
      connection_or_close_for_error(chan->conn, 0);
      return;
    }
    if (tor_addr_eq(&addr, &(chan->conn->real_addr))) {
      connection_or_set_canonical(chan->conn, 1);
      break;
    }
    cp = next;
    --n_other_addrs;
  }

  /* Act on apparent skew. */
  /** Warn when we get a netinfo skew with at least this value. */
#define NETINFO_NOTICE_SKEW 3600
  if (labs(apparent_skew) > NETINFO_NOTICE_SKEW &&
      router_get_by_id_digest(chan->conn->identity_digest)) {
    char dbuf[64];
    int severity;
    /*XXXX be smarter about when everybody says we are skewed. */
    if (router_digest_is_trusted_dir(chan->conn->identity_digest))
      severity = LOG_WARN;
    else
      severity = LOG_INFO;
    format_time_interval(dbuf, sizeof(dbuf), apparent_skew);
    log_fn(severity, LD_GENERAL,
           "Received NETINFO cell with skewed time from "
           "server at %s:%d.  It seems that our clock is %s by %s, or "
           "that theirs is %s. Tor requires an accurate clock to work: "
           "please check your time and date settings.",
           chan->conn->base_.address,
           (int)(chan->conn->base_.port),
           apparent_skew > 0 ? "ahead" : "behind",
           dbuf,
           apparent_skew > 0 ? "behind" : "ahead");
    if (severity == LOG_WARN) /* only tell the controller if an authority */
      control_event_general_status(LOG_WARN,
                          "CLOCK_SKEW SKEW=%ld SOURCE=OR:%s:%d",
                          apparent_skew,
                          chan->conn->base_.address,
                          chan->conn->base_.port);
  }

  /* XXX maybe act on my_apparent_addr, if the source is sufficiently
   * trustworthy. */

  if (! chan->conn->handshake_state->sent_netinfo) {
    /* If we were prepared to authenticate, but we never got an AUTH_CHALLENGE
     * cell, then we would not previously have sent a NETINFO cell. Do so
     * now. */
    if (connection_or_send_netinfo(chan->conn) < 0) {
      connection_or_close_for_error(chan->conn, 0);
      return;
    }
  }

  if (connection_or_set_state_open(chan->conn) < 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Got good NETINFO cell from %s:%d; but "
           "was unable to make the OR connection become open.",
           safe_str_client(chan->conn->base_.address),
           chan->conn->base_.port);
    connection_or_close_for_error(chan->conn, 0);
  } else {
    log_info(LD_OR,
             "Got good NETINFO cell from %s:%d; OR connection is now "
             "open, using protocol version %d. Its ID digest is %s. "
             "Our address is apparently %s.",
             safe_str_client(chan->conn->base_.address),
             chan->conn->base_.port,
             (int)(chan->conn->link_proto),
             hex_str(TLS_CHAN_TO_BASE(chan)->identity_digest,
                     DIGEST_LEN),
             tor_addr_is_null(&my_apparent_addr) ?
             "<none>" : fmt_and_decorate_addr(&my_apparent_addr));
  }
  assert_connection_ok(TO_CONN(chan->conn),time(NULL));
}

/**
 * Process a CERTS cell from a channel.
 *
 * This function is called to process an incoming CERTS cell on a
 * channel_tls_t:
 *
 * If the other side should not have sent us a CERTS cell, or the cell is
 * malformed, or it is supposed to authenticate the TLS key but it doesn't,
 * then mark the connection.
 *
 * If the cell has a good cert chain and we're doing a v3 handshake, then
 * store the certificates in or_handshake_state.  If this is the client side
 * of the connection, we then authenticate the server or mark the connection.
 * If it's the server side, wait for an AUTHENTICATE cell.
 */

STATIC void
channel_tls_process_certs_cell(var_cell_t *cell, channel_tls_t *chan)
{
#define MAX_CERT_TYPE_WANTED OR_CERT_TYPE_AUTH_1024
  tor_x509_cert_t *certs[MAX_CERT_TYPE_WANTED + 1];
  int n_certs, i;
  certs_cell_t *cc = NULL;

  int send_netinfo = 0;

  memset(certs, 0, sizeof(certs));
  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad CERTS cell from %s:%d: %s",          \
           safe_str(chan->conn->base_.address),                 \
           chan->conn->base_.port, (s));                        \
    connection_or_close_for_error(chan->conn, 0);               \
    goto err;                                                   \
  } while (0)

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake!");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (chan->conn->handshake_state->received_certs_cell)
    ERR("We already got one");
  if (chan->conn->handshake_state->authenticated) {
    /* Should be unreachable, but let's make sure. */
    ERR("We're already authenticated!");
  }
  if (cell->payload_len < 1)
    ERR("It had no body");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  if (certs_cell_parse(&cc, cell->payload, cell->payload_len) < 0)
    ERR("It couldn't be parsed.");

  n_certs = cc->n_certs;

  for (i = 0; i < n_certs; ++i) {
    certs_cell_cert_t *c = certs_cell_get_certs(cc, i);

    uint16_t cert_type = c->cert_type;
    uint16_t cert_len = c->cert_len;
    uint8_t *cert_body = certs_cell_cert_getarray_body(c);

    if (cert_type > MAX_CERT_TYPE_WANTED)
      continue;

    tor_x509_cert_t *cert = tor_x509_cert_decode(cert_body, cert_len);
    if (!cert) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Received undecodable certificate in CERTS cell from %s:%d",
             safe_str(chan->conn->base_.address),
             chan->conn->base_.port);
    } else {
      if (certs[cert_type]) {
        tor_x509_cert_free(cert);
        ERR("Duplicate x509 certificate");
      } else {
        certs[cert_type] = cert;
      }
    }
  }

  tor_x509_cert_t *id_cert = certs[OR_CERT_TYPE_ID_1024];
  tor_x509_cert_t *auth_cert = certs[OR_CERT_TYPE_AUTH_1024];
  tor_x509_cert_t *link_cert = certs[OR_CERT_TYPE_TLS_LINK];

  if (chan->conn->handshake_state->started_here) {
    int severity;
    if (! (id_cert && link_cert))
      ERR("The certs we wanted were missing");
    /* Okay. We should be able to check the certificates now. */
    if (! tor_tls_cert_matches_key(chan->conn->tls, link_cert)) {
      ERR("The link certificate didn't match the TLS public key");
    }
    /* Note that this warns more loudly about time and validity if we were
    * _trying_ to connect to an authority, not necessarily if we _did_ connect
    * to one. */
    if (router_digest_is_trusted_dir(
          TLS_CHAN_TO_BASE(chan)->identity_digest))
      severity = LOG_WARN;
    else
      severity = LOG_PROTOCOL_WARN;

    if (! tor_tls_cert_is_valid(severity, link_cert, id_cert, 0))
      ERR("The link certificate was not valid");
    if (! tor_tls_cert_is_valid(severity, id_cert, id_cert, 1))
      ERR("The ID certificate was not valid");

    chan->conn->handshake_state->authenticated = 1;
    {
      const digests_t *id_digests = tor_x509_cert_get_id_digests(id_cert);
      crypto_pk_t *identity_rcvd;
      if (!id_digests)
        ERR("Couldn't compute digests for key in ID cert");

      identity_rcvd = tor_tls_cert_get_key(id_cert);
      if (!identity_rcvd)
        ERR("Internal error: Couldn't get RSA key from ID cert.");
      memcpy(chan->conn->handshake_state->authenticated_peer_id,
             id_digests->d[DIGEST_SHA1], DIGEST_LEN);
      channel_set_circid_type(TLS_CHAN_TO_BASE(chan), identity_rcvd,
                chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);
      crypto_pk_free(identity_rcvd);
    }

    if (connection_or_client_learned_peer_id(chan->conn,
            chan->conn->handshake_state->authenticated_peer_id) < 0)
      ERR("Problem setting or checking peer id");

    log_info(LD_OR,
             "Got some good certificates from %s:%d: Authenticated it.",
             safe_str(chan->conn->base_.address), chan->conn->base_.port);

    chan->conn->handshake_state->id_cert = id_cert;
    certs[OR_CERT_TYPE_ID_1024] = NULL;

    if (!public_server_mode(get_options())) {
      /* If we initiated the connection and we are not a public server, we
       * aren't planning to authenticate at all.  At this point we know who we
       * are talking to, so we can just send a netinfo now. */
      send_netinfo = 1;
    }
  } else {
    if (! (id_cert && auth_cert))
      ERR("The certs we wanted were missing");

    /* Remember these certificates so we can check an AUTHENTICATE cell */
    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, auth_cert, id_cert, 1))
      ERR("The authentication certificate was not valid");
    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, id_cert, id_cert, 1))
      ERR("The ID certificate was not valid");

    log_info(LD_OR,
             "Got some good certificates from %s:%d: "
             "Waiting for AUTHENTICATE.",
             safe_str(chan->conn->base_.address),
             chan->conn->base_.port);
    /* XXXX check more stuff? */

    chan->conn->handshake_state->id_cert = id_cert;
    chan->conn->handshake_state->auth_cert = auth_cert;
    certs[OR_CERT_TYPE_ID_1024] = certs[OR_CERT_TYPE_AUTH_1024] = NULL;
  }

  chan->conn->handshake_state->received_certs_cell = 1;

  if (send_netinfo) {
    if (connection_or_send_netinfo(chan->conn) < 0) {
      log_warn(LD_OR, "Couldn't send netinfo cell");
      connection_or_close_for_error(chan->conn, 0);
      goto err;
    }
  }

 err:
  for (unsigned i = 0; i < ARRAY_LENGTH(certs); ++i) {
    tor_x509_cert_free(certs[i]);
  }
  certs_cell_free(cc);
#undef ERR
}

/**
 * Process an AUTH_CHALLENGE cell from a channel_tls_t
 *
 * This function is called to handle an incoming AUTH_CHALLENGE cell on a
 * channel_tls_t; if we weren't supposed to get one (for example, because we're
 * not the originator of the channel), or it's ill-formed, or we aren't doing
 * a v3 handshake, mark the channel.  If the cell is well-formed but we don't
 * want to authenticate, just drop it.  If the cell is well-formed *and* we
 * want to authenticate, send an AUTHENTICATE cell and then a NETINFO cell.
 */

STATIC void
channel_tls_process_auth_challenge_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int n_types, i, use_type = -1;
  auth_challenge_cell_t *ac = NULL;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTH_CHALLENGE cell from %s:%d: %s", \
           safe_str(chan->conn->base_.address),                 \
           chan->conn->base_.port, (s));                        \
    connection_or_close_for_error(chan->conn, 0);               \
    goto done;                                                  \
  } while (0)

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not currently doing a v3 handshake");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (!(chan->conn->handshake_state->started_here))
    ERR("We didn't originate this connection");
  if (chan->conn->handshake_state->received_auth_challenge)
    ERR("We already received one");
  if (!(chan->conn->handshake_state->received_certs_cell))
    ERR("We haven't gotten a CERTS cell yet");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  if (auth_challenge_cell_parse(&ac, cell->payload, cell->payload_len) < 0)
    ERR("It was not well-formed.");

  n_types = ac->n_methods;

  /* Now see if there is an authentication type we can use */
  for (i = 0; i < n_types; ++i) {
    uint16_t authtype = auth_challenge_cell_get_methods(ac, i);
    if (authtype == AUTHTYPE_RSA_SHA256_TLSSECRET)
      use_type = authtype;
  }

  chan->conn->handshake_state->received_auth_challenge = 1;

  if (! public_server_mode(get_options())) {
    /* If we're not a public server then we don't want to authenticate on a
       connection we originated, and we already sent a NETINFO cell when we
       got the CERTS cell. We have nothing more to do. */
    goto done;
  }

  if (use_type >= 0) {
    log_info(LD_OR,
             "Got an AUTH_CHALLENGE cell from %s:%d: Sending "
             "authentication",
             safe_str(chan->conn->base_.address),
             chan->conn->base_.port);

    if (connection_or_send_authenticate_cell(chan->conn, use_type) < 0) {
      log_warn(LD_OR,
               "Couldn't send authenticate cell");
      connection_or_close_for_error(chan->conn, 0);
      goto done;
    }
  } else {
    log_info(LD_OR,
             "Got an AUTH_CHALLENGE cell from %s:%d, but we don't "
             "know any of its authentication types. Not authenticating.",
             safe_str(chan->conn->base_.address),
             chan->conn->base_.port);
  }

  if (connection_or_send_netinfo(chan->conn) < 0) {
    log_warn(LD_OR, "Couldn't send netinfo cell");
    connection_or_close_for_error(chan->conn, 0);
    goto done;
  }

 done:
  auth_challenge_cell_free(ac);

#undef ERR
}

/**
 * Process an AUTHENTICATE cell from a channel_tls_t
 *
 * If it's ill-formed or we weren't supposed to get one or we're not doing a
 * v3 handshake, then mark the connection.  If it does not authenticate the
 * other side of the connection successfully (because it isn't signed right,
 * we didn't get a CERTS cell, etc) mark the connection.  Otherwise, accept
 * the identity of the router on the other side of the connection.
 */

STATIC void
channel_tls_process_authenticate_cell(var_cell_t *cell, channel_tls_t *chan)
{
  uint8_t expected[V3_AUTH_FIXED_PART_LEN+256];
  const uint8_t *auth;
  int authlen;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTHENTICATE cell from %s:%d: %s",   \
           safe_str(chan->conn->base_.address),                 \
           chan->conn->base_.port, (s));                        \
    connection_or_close_for_error(chan->conn, 0);               \
    return;                                                     \
  } while (0)

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (chan->conn->handshake_state->started_here)
    ERR("We originated this connection");
  if (chan->conn->handshake_state->received_authenticate)
    ERR("We already got one!");
  if (chan->conn->handshake_state->authenticated) {
    /* Should be impossible given other checks */
    ERR("The peer is already authenticated");
  }
  if (!(chan->conn->handshake_state->received_certs_cell))
    ERR("We never got a certs cell");
  if (chan->conn->handshake_state->auth_cert == NULL)
    ERR("We never got an authentication certificate");
  if (chan->conn->handshake_state->id_cert == NULL)
    ERR("We never got an identity certificate");
  if (cell->payload_len < 4)
    ERR("Cell was way too short");

  auth = cell->payload;
  {
    uint16_t type = ntohs(get_uint16(auth));
    uint16_t len = ntohs(get_uint16(auth+2));
    if (4 + len > cell->payload_len)
      ERR("Authenticator was truncated");

    if (type != AUTHTYPE_RSA_SHA256_TLSSECRET)
      ERR("Authenticator type was not recognized");

    auth += 4;
    authlen = len;
  }

  if (authlen < V3_AUTH_BODY_LEN + 1)
    ERR("Authenticator was too short");

  ssize_t bodylen =
    connection_or_compute_authenticate_cell_body(
                        chan->conn, expected, sizeof(expected), NULL, 1);
  if (bodylen < 0 || bodylen != V3_AUTH_FIXED_PART_LEN)
    ERR("Couldn't compute expected AUTHENTICATE cell body");

  if (tor_memneq(expected, auth, bodylen))
    ERR("Some field in the AUTHENTICATE cell body was not as expected");

  {
    crypto_pk_t *pk = tor_tls_cert_get_key(
                                   chan->conn->handshake_state->auth_cert);
    char d[DIGEST256_LEN];
    char *signed_data;
    size_t keysize;
    int signed_len;

    if (!pk)
      ERR("Internal error: couldn't get RSA key from AUTH cert.");
    crypto_digest256(d, (char*)auth, V3_AUTH_BODY_LEN, DIGEST_SHA256);

    keysize = crypto_pk_keysize(pk);
    signed_data = tor_malloc(keysize);
    signed_len = crypto_pk_public_checksig(pk, signed_data, keysize,
                                           (char*)auth + V3_AUTH_BODY_LEN,
                                           authlen - V3_AUTH_BODY_LEN);
    crypto_pk_free(pk);
    if (signed_len < 0) {
      tor_free(signed_data);
      ERR("Signature wasn't valid");
    }
    if (signed_len < DIGEST256_LEN) {
      tor_free(signed_data);
      ERR("Not enough data was signed");
    }
    /* Note that we deliberately allow *more* than DIGEST256_LEN bytes here,
     * in case they're later used to hold a SHA3 digest or something. */
    if (tor_memneq(signed_data, d, DIGEST256_LEN)) {
      tor_free(signed_data);
      ERR("Signature did not match data to be signed.");
    }
    tor_free(signed_data);
  }

  /* Okay, we are authenticated. */
  chan->conn->handshake_state->received_authenticate = 1;
  chan->conn->handshake_state->authenticated = 1;
  chan->conn->handshake_state->digest_received_data = 0;
  {
    crypto_pk_t *identity_rcvd =
      tor_tls_cert_get_key(chan->conn->handshake_state->id_cert);
    const digests_t *id_digests =
      tor_x509_cert_get_id_digests(chan->conn->handshake_state->id_cert);

    /* This must exist; we checked key type when reading the cert. */
    tor_assert(id_digests);

    memcpy(chan->conn->handshake_state->authenticated_peer_id,
           id_digests->d[DIGEST_SHA1], DIGEST_LEN);

    channel_set_circid_type(TLS_CHAN_TO_BASE(chan), identity_rcvd,
               chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);
    crypto_pk_free(identity_rcvd);

    connection_or_init_conn_from_address(chan->conn,
                  &(chan->conn->base_.addr),
                  chan->conn->base_.port,
                  (const char*)(chan->conn->handshake_state->
                    authenticated_peer_id),
                  0);

    log_info(LD_OR,
             "Got an AUTHENTICATE cell from %s:%d: Looks good.",
             safe_str(chan->conn->base_.address),
             chan->conn->base_.port);
  }

#undef ERR
}

