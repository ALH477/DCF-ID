# Anchors (vendored)

Copied from `examples/dcfid_gate/README.md` in Exsecutor between its `anchors:begin` / `anchors:end`
markers (see PROVENANCE.md). `cargo test --lib` parses this table and asserts that src/gate.rs
gives these verdicts. Input spelling: `\xNN` a byte, `{c*N}` N copies of c, `\\` a backslash;
`n` is `=` for the byte count, else the length handed to the gate.

<!-- anchors:begin -->
| fn | input | n | verdict |
|---|---|---|---|
| nomen | `alice` | = | 0 |
| nomen | `bob` | = | 0 |
| nomen | `a_b-C9` | = | 0 |
| nomen | `ab` | = | 3 |
| nomen | `a` | 0 | 1 |
| nomen | `{a*32}` | = | 0 |
| nomen | `{a*33}` | = | 2 |
| nomen | `{a*3}` | 4294967296 | 2 |
| nomen | `al ice` | = | 4 |
| nomen | `al\x00ice` | = | 4 |
| nomen | `alice\x0a` | = | 4 |
| nomen | `\xd0\xb0dmin` | = | 4 |
| nomen | `adm\xc3\xafn` | = | 4 |
| nomen | `a.b` | = | 4 |
| nomen | `a@b` | = | 4 |
| nomen | `a/b` | = | 4 |
| nomen | `{a*30}\xc3\xa9` | = | 4 |
| nomen | `---` | = | 0 |
| nomen | `{a*3}` | 18446744073709551615 | 2 |
| signum:0 | `{A*64}` | = | 0 |
| signum:0 | `{a*63}` | = | 2 |
| signum:0 | `{a*65}` | = | 2 |
| signum:0 | `{a*63}-` | = | 3 |
| signum:0 | `{a*63}\x00` | = | 3 |
| signum:0 | `a` | 0 | 2 |
| signum:0 | `{a*32}` | = | 2 |
| signum:0 | `{0*32}{9*32}` | = | 0 |
| signum:0 | `{a*3}` | 18446744073709551615 | 2 |
| signum:1 | `{Z*32}` | = | 0 |
| signum:1 | `{Z*31}` | = | 2 |
| signum:1 | `{Z*33}` | = | 2 |
| signum:1 | `{Z*31}_` | = | 3 |
| signum:1 | `{Z*64}` | = | 2 |
| signum:1 | `{Z*31}\xc3\xa9` | = | 2 |
| signum:1 | `{Z*30}\xc3\xa9` | = | 3 |
| signum:2 | `{a*32}` | = | 1 |
| signum:255 | `{a*64}` | = | 1 |
| signum:3 | `{a*64}` | = | 1 |
| summam | `0` | = | 1 |
| summam | `100` | = | 1 |
| summam | `249` | = | 1 |
| summam | `250` | = | 0 |
| summam | `500` | = | 0 |
| summam | `9999` | = | 0 |
| summam | `10000` | = | 0 |
| summam | `10001` | = | 2 |
| summam | `4294967296` | = | 2 |
| summam | `18446744073709551615` | = | 2 |
| forma | `t=1492774577,v1={a*64}` | = | 0 |
| forma | `t=1492774577,v1={a*64},v0={b*64}` | = | 0 |
| forma | `v1={a*64},t=1` | = | 0 |
| forma | `t=1,v1={0*64},v1={f*64}` | = | 0 |
| forma | `t=123456789012,v1={a*64}` | = | 0 |
| forma | `t=1,v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64}` | = | 0 |
| forma | `t=1,v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64},v1={a*64},x` | = | 6 |
| forma | `t` | 0 | 1 |
| forma | `{t*513}` | = | 2 |
| forma | `t=1` | = | 9 |
| forma | `v1={a*64}` | = | 8 |
| forma | `t=1,v0={a*64}` | = | 9 |
| forma | `t=1,v1={a*63}` | = | 5 |
| forma | `t=1,v1={a*65}` | = | 5 |
| forma | `t=1,v1={A*64}` | = | 5 |
| forma | `t=1,v1={a*64}\x00` | = | 5 |
| forma | `t=1,v0={a*10}` | = | 5 |
| forma | `t=,v1={a*64}` | = | 4 |
| forma | `t=1234567890123,v1={a*64}` | = | 4 |
| forma | `t=12x,v1={a*64}` | = | 4 |
| forma | `t=1\x0a,v1={a*64}` | = | 4 |
| forma | `t=-1,v1={a*64}` | = | 4 |
| forma | `t=1.5,v1={a*64}` | = | 4 |
| forma | `t=1, v1={a*64}` | = | 3 |
| forma | `t=1,,v1={a*64}` | = | 3 |
| forma | `,t=1,v1={a*64}` | = | 3 |
| forma | `t=1,v1={a*64},` | = | 3 |
| forma | `t=1,v2={a*64}` | = | 3 |
| forma | `x=1` | = | 3 |
| forma | `T=1,v1={a*64}` | = | 3 |
| forma | `t=1,v1` | = | 3 |
| forma | `t=1,v` | = | 3 |
| forma | `t=1;v1={a*64}` | = | 4 |
| forma | `t=1,t=2,v1={a*64}` | = | 7 |
| forma | `t=1,v1={a*64},t=2` | = | 7 |
<!-- anchors:end -->
