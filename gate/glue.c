/* gate/glue.c -- see glue.h. Written for DCF-ID, not emitted by exsc.
 *
 * The one setjmp of the program is inside exs_tutela_curre (tutela.c); the
 * thunks here contain none, so C11 7.13.2.1p3 is discharged once, in tutela.c.
 * Between the guard and a trap there are only frames of the emitted gate and
 * of these thunks -- no Rust frame, no lock (tutela.h precondition P1). */
#include <stdint.h>
#include "dcfid_gate.gen.h"
#include "tutela.h"
#include "glue.h"

struct ctx {
  unsigned char *b;
  uint64_t n;
  uint64_t genus;
  uint64_t r;
};

static void t_nomen(void *p)  { struct ctx *c = p; c->r = exs_admitte_nomen(c->b, c->n); }
static void t_signum(void *p) { struct ctx *c = p; c->r = exs_admitte_signum(c->b, c->n, c->genus); }
static void t_summam(void *p) { struct ctx *c = p; c->r = exs_admitte_summam(c->n); }
static void t_forma(void *p)  { struct ctx *c = p; c->r = exs_admitte_formam_signaturae(c->b, c->n); }
static void t_ipv4(void *p)   { struct ctx *c = p; c->r = exs_admitte_ipv4(c->b, c->n); }
static void t_trap(void *p)   { struct ctx *c = p; exsrt_abortus((unsigned)c->n); }

static unsigned run(exs_opus *f, struct ctx *c, uint64_t *out)
{
  unsigned k = exs_tutela_curre(f, c);
  if (k == 0) *out = c->r;
  return k;
}

unsigned dcfid_glue_nomen(unsigned char *b, uint64_t n, uint64_t *out)
{ struct ctx c = { b, n, 0, 0 }; return run(t_nomen, &c, out); }

unsigned dcfid_glue_signum(unsigned char *b, uint64_t n, uint64_t genus, uint64_t *out)
{ struct ctx c = { b, n, genus, 0 }; return run(t_signum, &c, out); }

unsigned dcfid_glue_summam(uint64_t cents, uint64_t *out)
{ struct ctx c = { 0, cents, 0, 0 }; return run(t_summam, &c, out); }

unsigned dcfid_glue_forma(unsigned char *b, uint64_t n, uint64_t *out)
{ struct ctx c = { b, n, 0, 0 }; return run(t_forma, &c, out); }

unsigned dcfid_glue_ipv4(unsigned char *b, uint64_t n, uint64_t *out)
{ struct ctx c = { b, n, 0, 0 }; return run(t_ipv4, &c, out); }

unsigned dcfid_glue_selftest_trap(unsigned kind)
{ struct ctx c = { 0, kind, 0, 0 }; uint64_t sink = 0; return run(t_trap, &c, &sink); }

unsigned dcfid_glue_depth(void)
{ return exs_tutela_profunditas(); }
