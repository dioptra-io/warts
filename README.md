# 💢 warts

[![Build](https://img.shields.io/github/workflow/status/dioptra-io/warts/Build)](https://github.com/dioptra-io/warts/actions/workflows/build.yml)
[![Coverage](https://img.shields.io/codecov/c/github/dioptra-io/warts)](https://app.codecov.io/gh/dioptra-io/warts)
[![crates.io](https://img.shields.io/crates/v/warts?logo=crates)](https://crates.io/crates/warts/)
[![docs.rs](https://img.shields.io/docsrs/warts)](https://docs.rs/warts/)

This crate implements reading and writing
[`warts(5)`](https://www.caida.org/catalog/software/scamper/man/warts.5.pdf)
files produced by CAIDA's [Scamper](https://www.caida.org/catalog/software/scamper/) tool.  
It relies on the excellent [deku](https://github.com/sharksforarms/deku) crate for serializing and deserializing the binary format.

## Usage

You can run one of the examples in [`examples/`](examples/):

```bash
cargo run --release --example dump data/trace_google_dns_v6_default.warts
cargo run --release --example read_traceroute data/trace_google_dns_v6_default.warts
cargo run --release --example write_traceroute > test.warts
```

To use in your own project, add the following dependency to `Cargo.toml`:
```toml
[dependencies]
warts = "0.2"
```

## Limitations

The following features are currently not implemented:

- [ ] DoubleTree and PMTUD data
- [ ] `tsprespec` data
- [ ] Streaming reading

## Performance

Time to parse and print the traceroutes from `abz-uk.team-probing.c009127.20210202.warts` (52MB).  
Measured  with [hyperfine](https://github.com/sharkdp/hyperfine) on a 2020 M1 MacBook Air.

| Library                                                                              | Time (s)   |
|--------------------------------------------------------------------------------------|------------|
| warts / `read_traceroute`                                                            | 0.797      |
| [Scamper](https://www.caida.org/catalog/software/scamper/) / `sc_warts2text`         | 1.125      |
| [pywarts](https://github.com/drakkar-lig/scamper-pywarts) / `parse_from_stdin.py`    | 12.405     |
| [cmand/scamper](https://github.com/cmand/scamper) / `sc_warts2text.py`               | 21.207     |

### Object types

| Type     | Structure                 | Name                         | Implemented |
|----------|---------------------------|------------------------------|-------------|
| `0x0001` | `scamper_list_t`          | List                         | Y           |
| `0x0002` | `scamper_cycle_t`         | Cycle start                  | Y           |
| `0x0003` | `scamper_cycle_t`         | Cycle definition             | Y           |
| `0x0004` | `scamper_cycle_t`         | Cycle stop                   | Y           |
| `0x0005` | `scamper_addr_t`          | Address (deprecated)         | Y           |
| `0x0006` | `scamper_trace_t`         | Traceroute                   | Y           |
| `0x0007` | `scamper_ping_t`          | Ping                         | Y           |
| `0x0008` | `scamper_tracelb_t`       | MDA traceroute               | Y           |
| `0x0009` | `scamper_dealias_t`       | Alias resolution             | N           |
| `0x000a` | `scamper_neighbourdisc_t` | Neighbour discovery          | N           |
| `0x000b` | `scamper_tbit_t`          | TCP behaviour inference tool | N           |
| `0x000c` | `scamper_sting_t`         | Sting                        | N           |
| `0x000d` | `scamper_sniff_t`         | Sniff                        | N           |
