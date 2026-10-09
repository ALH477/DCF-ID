// exsecutor: the Rust face of a library unit (exsc --emitte rs). Generated,
// never hand-edited: one declaration per `publica` function the unit
// defines, in the unit's own C ABI -- uint64_t is u64, unsigned char * is
// *mut u8, float is f32, double is f64. The unit imports one symbol, which
// the host supplies and which must not return:
//     _Noreturn void exsrt_abortus(unsigned kind);
//     #[no_mangle] pub extern "C" fn exsrt_abortus(kind: u32) -> ! { ... }
// Above each declaration, its IR signature: a u64 carries the named width in
// canonical form (a uN zero-extended, an iN sign-extended); a value outside
// that width is outside the contract, and what the unit does with one is
// unspecified. docs/design/c-backend.md D1, D5, D9.
unsafe extern "C" {
    // (ptr, u64) -> u8
    pub fn exs_admitte_ipv4(p0: *mut u8, p1: u64) -> u64;
    // (ptr, u64) -> u8
    pub fn exs_ordo_ipv4(p0: *mut u8, p1: u64) -> u64;
    // (ptr, u64) -> u8
    pub fn exs_admitte_portum(p0: *mut u8, p1: u64) -> u64;
    // (ptr, u64) -> u8
    pub fn exs_admitte_intervallum(p0: *mut u8, p1: u64) -> u64;
    // (ptr, u64) -> u8
    pub fn exs_admitte_nomen(p0: *mut u8, p1: u64) -> u64;
    // (ptr, u64, u8) -> u8
    pub fn exs_admitte_signum(p0: *mut u8, p1: u64, p2: u64) -> u64;
    // (u64) -> u8
    pub fn exs_admitte_summam(p0: u64) -> u64;
    // (ptr, u64) -> u8
    pub fn exs_admitte_formam_signaturae(p0: *mut u8, p1: u64) -> u64;
}
