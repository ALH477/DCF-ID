// Compiles the vendored Exsecutor gate (gate/): the C that `exsc --emitte c`
// emitted from examples/dcf_net_gate and examples/dcfid_gate, the trap guard
// (tutela.c) and the glue that runs each gate call under it. Building needs a
// C11 compiler (cc); it does NOT need fasmg or exsc -- gate/PROVENANCE.md says
// how the files were produced and scripts/check-gate-fresh.sh re-checks them
// when exsc is available.
fn main() {
    let mut b = cc::Build::new();
    b.std("c11")
        .include("gate")
        .file("gate/dcfid_gate.gen.c")
        .file("gate/tutela.c")
        .file("gate/glue.c")
        .warnings(true)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-fno-fast-math")
        .opt_level(2);
    b.compile("dcfid_gate");
    println!("cargo:rerun-if-changed=gate");
    println!("cargo:rerun-if-changed=build.rs");
}
