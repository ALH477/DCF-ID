/* gate/glue.h -- the C side of src/gate.rs: every gate call, run under a
 * tutela guard so that a trap returns to Rust instead of ending the process.
 *
 * Each function returns 0 when the gate answered (the verdict is in *out), or
 * the trap kind (never 0) when it trapped. The gates are total, so a trap
 * should be unreachable; this is defence in depth, and fails CLOSED -- the
 * Rust side treats a trap as a refusal.
 *
 * `b` points at a buffer of EXACTLY the gate's capacity (32, 64, 512, 16 bytes),
 * all readable; src/gate.rs copies its input into one. */
#ifndef DCFID_GLUE_H
#define DCFID_GLUE_H
#include <stdint.h>

unsigned dcfid_glue_nomen(unsigned char *b, uint64_t n, uint64_t *out);
unsigned dcfid_glue_signum(unsigned char *b, uint64_t n, uint64_t genus, uint64_t *out);
unsigned dcfid_glue_summam(uint64_t cents, uint64_t *out);
unsigned dcfid_glue_forma(unsigned char *b, uint64_t n, uint64_t *out);
unsigned dcfid_glue_ipv4(unsigned char *b, uint64_t n, uint64_t *out);

/* Test hook: raises exsrt_abortus(kind) inside a guard and returns the kind the
 * guard saw. Proves, from Rust and from several threads at once, that the trap
 * path returns instead of aborting. Never called by the service. */
unsigned dcfid_glue_selftest_trap(unsigned kind);
/* Guards the calling thread has open (0 outside a call). */
unsigned dcfid_glue_depth(void);
#endif
