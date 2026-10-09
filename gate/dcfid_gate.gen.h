/* exsecutor: the C face of a library unit (exsc --emitte h). Generated,
 * never hand-edited: one prototype per `publica` function the unit defines,
 * spelled exactly as the unit's own prototype, then the one symbol the unit
 * imports. The host supplies exsrt_abortus; only a trap reaches it, and it
 * must not return. Above each prototype, its IR signature: a uint64_t carries
 * the named width in canonical form (a uN zero-extended, an iN sign-extended);
 * a value outside that width is outside the contract, and what the unit does
 * with one is unspecified. docs/design/c-backend.md D1, D5, D9. */
#ifndef EXSECUTOR_FACIES_8FF8F533A7D1E7B5_H
#define EXSECUTOR_FACIES_8FF8F533A7D1E7B5_H
#include <stdint.h>

/* (ptr, u64) -> u8 */
uint64_t exs_admitte_ipv4(unsigned char *p0, uint64_t p1);
/* (ptr, u64) -> u8 */
uint64_t exs_ordo_ipv4(unsigned char *p0, uint64_t p1);
/* (ptr, u64) -> u8 */
uint64_t exs_admitte_portum(unsigned char *p0, uint64_t p1);
/* (ptr, u64) -> u8 */
uint64_t exs_admitte_intervallum(unsigned char *p0, uint64_t p1);
/* (ptr, u64) -> u8 */
uint64_t exs_admitte_nomen(unsigned char *p0, uint64_t p1);
/* (ptr, u64, u8) -> u8 */
uint64_t exs_admitte_signum(unsigned char *p0, uint64_t p1, uint64_t p2);
/* (u64) -> u8 */
uint64_t exs_admitte_summam(uint64_t p0);
/* (ptr, u64) -> u8 */
uint64_t exs_admitte_formam_signaturae(unsigned char *p0, uint64_t p1);

_Noreturn void exsrt_abortus(unsigned kind);
#endif
