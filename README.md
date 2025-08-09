# KZG Commitments

Implementation of KZG commitments in Rust, as well as two variants optimized for multi-polynomial and multi-point opening and verification.

## Algorithms

This repository includes implementations for three algorithms, each based on a paper linked below:

1. [KZG10](https://iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
1. [GWC19](https://eprint.iacr.org/2019/953.pdf)
1. [DJBA21](https://eprint.iacr.org/2020/081.pdf)

## Documentation

To view documentation for the code, please run `cargo doc --release --open`.

## Usage
TBD

## Directory Structure

### `src/`

Contains the source code for the implementations.

### `tests/`

Contains tests. They can be run with `cargo test --release`.

### `benches/`

Contains code used to benchmark the speed of the implementations. They can be run with `cargo bench`.
> [!NOTE] 
Depending on your CPU processing power, this may take hours or days. 
You can edit `poly_deg_vals` and `poly_count_vals` in `benches/*_benchmarks.rs`
to remove some benchmarks and reduce the runtime.

### `results/`

Contains raw data for benchmarks run on an AMD Ryzen 5 7600. The time displayed is averaged 
over 100/50/25 iterations, depending on the size of the parameters. The files contain a description
of the benchmark followed by the runtime on the next line. The description is formatted as:
```
{implementation}-{curve}/{operation} {polynomial count} | {polynomial degree}
```

