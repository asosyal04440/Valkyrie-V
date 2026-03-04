//! Valkyrie-V Performance Benchmarks
//!
//! Comprehensive benchmarks for core VMM subsystems using Criterion.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use valkyrie_v::vmm;

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY COMPRESSION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_memory_compression(c: &mut Criterion) {
    use vmm::memory_compress::{CompressedMemoryPool, PAGE_SIZE};
    
    let mut group = c.benchmark_group("memory_compression");
    
    // Page compression throughput
    group.throughput(Throughput::Bytes(PAGE_SIZE as u64));
    
    let page_data = [0x42u8; PAGE_SIZE];
    
    group.bench_function("compress_page_uniform", |b| {
        let mut pool = CompressedMemoryPool::new();
        pool.enable(80, 1024 * 1024 * 1024);
        pool.min_ratio.store(0, core::sync::atomic::Ordering::Release);
        
        b.iter(|| {
            let result = pool.compress_page(
                black_box(0x1000),
                black_box(1),
                black_box(1),
                black_box(&page_data),
            );
            black_box(result);
        });
    });
    
    // Decompression benchmark
    group.bench_function("decompress_page", |b| {
        let mut pool = CompressedMemoryPool::new();
        pool.enable(80, 1024 * 1024 * 1024);
        pool.min_ratio.store(0, core::sync::atomic::Ordering::Release);
        
        let slot = pool.compress_page(0x1000, 1, 1, &page_data).unwrap();
        let mut output = [0u8; PAGE_SIZE];
        
        b.iter(|| {
            let result = pool.decompress_page(black_box(slot), black_box(&mut output));
            black_box(result);
        });
    });
    
    // Compression stats access
    group.bench_function("compression_stats", |b| {
        let pool = CompressedMemoryPool::new();
        
        b.iter(|| {
            black_box(pool.pages_compressed.load(core::sync::atomic::Ordering::Acquire));
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// SCHEDULER BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_scheduler(c: &mut Criterion) {
    use vmm::sched_adv::{AdvancedCpuScheduler, sched_type};
    
    let mut group = c.benchmark_group("scheduler");
    
    // vCPU registration
    group.bench_function("register_vcpu", |b| {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        
        b.iter(|| {
            let result = sched.register_vcpu(
                black_box(0),
                black_box(1),
                black_box(128),
                black_box(256),
            );
            black_box(result);
        });
    });
    
    // vCPU state transitions
    group.bench_function("wake_vcpu", |b| {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        let idx = sched.register_vcpu(0, 1, 128, 256).unwrap();
        
        b.iter(|| {
            let result = sched.wake_vcpu(black_box(idx));
            black_box(result);
        });
    });
    
    // Scheduling decision
    group.bench_function("schedule", |b| {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        let idx = sched.register_vcpu(0, 1, 128, 256).unwrap();
        sched.wake_vcpu(idx).unwrap();
        
        b.iter(|| {
            black_box(sched.schedule(black_box(0)));
        });
    });
    
    // Credit balancing
    group.bench_function("balance_credits", |b| {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        sched.credit_interval.store(0, core::sync::atomic::Ordering::Release);
        sched.register_vcpu(0, 1, 128, 256).unwrap();
        sched.register_vcpu(1, 1, 128, 512).unwrap();
        
        b.iter(|| {
            sched.balance_credits();
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// TLB SHOOTDOWN BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_tlb_shootdown(c: &mut Criterion) {
    use vmm::tlb::{TlbController, shootdown_type};
    
    let mut group = c.benchmark_group("tlb_shootdown");
    
    // Full TLB shootdown
    group.bench_function("request_full_shootdown", |b| {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        b.iter(|| {
            let result = ctrl.request_shootdown(
                black_box(shootdown_type::FULL),
                black_box(0xF),
                black_box(1),
                black_box(64),
            );
            black_box(result);
        });
    });
    
    // Single page shootdown
    group.bench_function("request_single_page", |b| {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        b.iter(|| {
            let result = ctrl.request_single_page(
                black_box(0x1000),
                black_box(1),
                black_box(0xF),
                black_box(1),
            );
            black_box(result);
        });
    });
    
    // Range shootdown
    group.bench_function("request_range", |b| {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        b.iter(|| {
            let result = ctrl.request_range(
                black_box(0x1000),
                black_box(16),
                black_box(0xF),
                black_box(1),
            );
            black_box(result);
        });
    });
    
    // Handle shootdown
    group.bench_function("handle_shootdown", |b| {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        
        b.iter(|| {
            ctrl.handle_shootdown(black_box(0), black_box(id));
        });
    });
    
    // PCID switching
    group.bench_function("switch_pcid", |b| {
        let ctrl = TlbController::new();
        ctrl.cpu_states[0].init(0);
        
        b.iter(|| {
            ctrl.switch_pcid(black_box(0), black_box(0), black_box(1));
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// VIRTIO BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_virtio(c: &mut Criterion) {
    use vmm::virtio_mq::{VirtioController, VirtioQueue, device_type};
    
    let mut group = c.benchmark_group("virtio");
    
    // Device registration
    group.bench_function("register_device", |b| {
        let mut ctrl = VirtioController::new();
        ctrl.enable(true, true, true);
        
        b.iter(|| {
            let result = ctrl.register_device(
                black_box(device_type::NET),
                black_box(1),
                black_box(0xFFFF),
            );
            black_box(result);
        });
    });
    
    // Queue initialization
    group.bench_function("queue_init", |b| {
        let mut queue = VirtioQueue::new();
        
        b.iter(|| {
            queue.init(black_box(0), black_box(256), black_box(false));
        });
    });
    
    // Queue address setup
    group.bench_function("queue_set_addresses", |b| {
        let mut queue = VirtioQueue::new();
        queue.init(0, 256, false);
        
        b.iter(|| {
            queue.set_addresses(
                black_box(0x100000),
                black_box(0x200000),
                black_box(0x300000),
            );
        });
    });
    
    // Auto affinity calculation
    group.bench_function("auto_affinity", |b| {
        let ctrl = VirtioController::new();
        let device = &ctrl.devices[0];
        device.init(1, device_type::NET, 1);
        device.add_queue(256, false).unwrap();
        device.add_queue(256, false).unwrap();
        device.add_queue(256, false).unwrap();
        device.add_queue(256, false).unwrap();
        
        b.iter(|| {
            device.auto_affinity(black_box(2));
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// MULTITENANT BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_multitenant(c: &mut Criterion) {
    use vmm::multitenant::MultiTenantController;
    
    let mut group = c.benchmark_group("multitenant");
    
    // Tenant creation
    group.bench_function("create_tenant", |b| {
        let mut ctrl = MultiTenantController::new();
        
        b.iter(|| {
            let result = ctrl.create_tenant(black_box(0));
            black_box(result);
        });
    });
    
    // Get tenant
    group.bench_function("get_tenant", |b| {
        let mut ctrl = MultiTenantController::new();
        ctrl.create_tenant(0).unwrap();
        
        b.iter(|| {
            black_box(ctrl.get_tenant(black_box(1)));
        });
    });
    
    // Delete tenant
    group.bench_function("delete_tenant", |b| {
        let mut ctrl = MultiTenantController::new();
        ctrl.create_tenant(0).unwrap();
        
        b.iter(|| {
            let result = ctrl.delete_tenant(black_box(1));
            black_box(result);
            ctrl.create_tenant(0).unwrap(); // Recreate for next iteration
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// ATOMIC OPERATIONS BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_atomics(c: &mut Criterion) {
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    
    let mut group = c.benchmark_group("atomics");
    
    // Atomic load
    group.bench_function("atomic_u32_load_acquire", |b| {
        let atomic = AtomicU32::new(42);
        
        b.iter(|| {
            black_box(atomic.load(Ordering::Acquire));
        });
    });
    
    // Atomic store
    group.bench_function("atomic_u32_store_release", |b| {
        let atomic = AtomicU32::new(0);
        
        b.iter(|| {
            atomic.store(black_box(42), Ordering::Release);
        });
    });
    
    // Atomic fetch_add
    group.bench_function("atomic_u64_fetch_add", |b| {
        let atomic = AtomicU64::new(0);
        
        b.iter(|| {
            black_box(atomic.fetch_add(black_box(1), Ordering::AcqRel));
        });
    });
    
    // Compare and swap
    group.bench_function("atomic_u32_compare_exchange", |b| {
        let atomic = AtomicU32::new(0);
        
        b.iter(|| {
            black_box(atomic.compare_exchange(
                black_box(0),
                black_box(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ));
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// HASH TABLE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_hash_table(c: &mut Criterion) {
    use vmm::memory_compress::Lz4HashTable;
    
    let mut group = c.benchmark_group("hash_table");
    
    let sample_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    
    // Hash calculation
    group.bench_function("hash4", |b| {
        let ht = Lz4HashTable::new();
        
        b.iter(|| {
            black_box(ht.hash4(black_box(&sample_data)));
        });
    });
    
    // Get position
    group.bench_function("hash_get", |b| {
        let ht = Lz4HashTable::new();
        ht.set(0x123, 42);
        
        b.iter(|| {
            black_box(ht.get(black_box(0x123)));
        });
    });
    
    // Set position
    group.bench_function("hash_set", |b| {
        let ht = Lz4HashTable::new();
        
        b.iter(|| {
            ht.set(black_box(0x123), black_box(42));
        });
    });
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// SCALING BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

fn bench_scaling(c: &mut Criterion) {
    use vmm::sched_adv::{AdvancedCpuScheduler, sched_type};
    
    let mut group = c.benchmark_group("scaling");
    
    // Scale with vCPU count
    for vcpu_count in [1, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("schedule_vcpus", vcpu_count),
            vcpu_count,
            |b, &count| {
                let mut sched = AdvancedCpuScheduler::new();
                sched.enable(4, sched_type::CREDIT);
                
                for i in 0..count {
                    let idx = sched.register_vcpu(i as u32 % 4, 1, 128, 256).unwrap();
                    sched.wake_vcpu(idx).unwrap();
                }
                
                b.iter(|| {
                    black_box(sched.schedule(black_box(0)));
                });
            },
        );
    }
    
    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// BENCHMARK GROUPS
// ═══════════════════════════════════════════════════════════════════════════

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(core::time::Duration::from_secs(2))
        .warm_up_time(core::time::Duration::from_millis(500));
    targets = 
        bench_atomics,
        bench_hash_table,
}

criterion_main!(benches);
