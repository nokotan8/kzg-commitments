mod util;

use crate::util::{benchmark_kzg10, benchmark_gwc19, benchmark_djba21};
use criterion::{Criterion, criterion_group, criterion_main};

use ark_bls12_381::Bls12_381;
use ark_bls12_377::Bls12_377;
use ark_bn254::Bn254;

fn benchmark(c: &mut Criterion) {
    let poly_deg = [8, 16, 32, 64, 128, 256];
    // tuples mean (num_poly/num_points, num_samples)
    let poly_count = [
        (1, 100), (2, 100), (4, 100), (8, 100), 
        (16, 50), (32, 50), (64, 50), (128, 50), 
        (256, 25), (512, 25), (1024, 25)
    ];

    benchmark_kzg10::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count[0..7]);
    benchmark_kzg10::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count[0..7]);
    benchmark_kzg10::<Bn254>(c, "bn254", &poly_deg, &poly_count[0..7]);

    benchmark_gwc19::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count[0..10]);
    benchmark_gwc19::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count[0..10]);
    benchmark_gwc19::<Bn254>(c, "bn254", &poly_deg, &poly_count[0..10]);
    
    benchmark_djba21::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count);
    benchmark_djba21::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count);
    benchmark_djba21::<Bn254>(c, "bn254", &poly_deg, &poly_count);
}

criterion_group!(bench, benchmark);
criterion_main!(bench);
