#[path = "../src/kzg_helpers.rs"]
mod kzg_helpers;

#[test]
fn kzg10_test() -> Result<(), ()> {
    let poly_deg_vals = [1, 10, 100, 1000];
    let poly_count_vals = [1, 10, 100, 1000];
    let point_count_vals = [1, 10, 100, 1000, 10000];

    for &poly_count in &poly_count_vals {
        for &poly_deg in &poly_deg_vals {
            for &point_count in &point_count_vals {
                if kzg_helpers::kzg10(poly_count, poly_deg, point_count) {
                    println!(
                        "params: polys: {}, deg: {}, points: {}",
                        poly_count, poly_deg, point_count
                    );
                    return Err(());
                }
            }
        }
    }

    return Ok(());
}
