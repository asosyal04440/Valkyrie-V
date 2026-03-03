use std::hint::black_box;
use std::time::Instant;

fn measure_loop(iterations: u64) -> u128 {
    let started = Instant::now();
    let mut value = 0u64;
    for index in 0..iterations {
        value = value.wrapping_add(index.rotate_left((index & 31) as u32));
    }
    black_box(value);
    started.elapsed().as_nanos()
}

fn main() {
    let warmup = measure_loop(100_000);
    let run = measure_loop(1_000_000);
    println!("micro_bench warmup_ns={warmup} run_ns={run}");
}
