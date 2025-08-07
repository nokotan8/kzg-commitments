use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
#[path = "../src/kzg_helpers.rs"] mod kzg_helpers;

// Benchmark function for varying parameter sizes
fn benchmark_kzg10(c: &mut Criterion) {
    let poly_deg_vals = [1, 10, 100, 1000];
    let poly_count_vals = [1, 10, 100, 1000];
    let point_count_vals = [1, 10, 100, 1000, 10000];

    for &poly_count in &poly_count_vals {
        for &poly_deg in &poly_deg_vals {
            for &point_count in &point_count_vals {
                c.bench_function(
                    &format!("kzg10_helper {} {} {}", poly_count, poly_deg, point_count),
                    |b| {
                        b.iter(|| {
                            black_box(kzg_helpers::kzg10(poly_count, poly_deg, point_count))
                        })
                    },
                );
            }
        }
    }
}

criterion_group!(benches, benchmark_kzg10);
criterion_main!(benches);
