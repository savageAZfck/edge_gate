use criterion::{black_box, criterion_group, criterion_main, Criterion};
use edge_gate::blind::Blinder;
use edge_gate::dedup::{feature_set, Deduper};
use edge_gate::filter::OutputFilter;

fn bench_blind(c: &mut Criterion) {
    let b = Blinder::new(
        &[
            "proj-nightingale".to_string(),
            "internal.acme.corp".to_string(),
        ],
        true,
        true,
    );
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"deploy proj-nightingale with key sk-abcdefghijklmnop1234567890 to internal.acme.corp and tell me about the migration plan for the database cluster"}]}"#;
    c.bench_function("blind_request_body", |bencher| {
        bencher.iter(|| b.blind(black_box(body)))
    });
}

fn bench_feature_set(c: &mut Criterion) {
    let prompt = "what is the best way to structure a rust project with multiple binaries and a shared library crate for the domain types";
    c.bench_function("feature_set", |bencher| {
        bencher.iter(|| feature_set(black_box(prompt)))
    });
}

fn bench_dedup_lookup(c: &mut Criterion) {
    // realistic: mostly-distinct prompts — the index prunes nearly all
    let d = Deduper::new(0.6, 1024);
    let topics = [
        "rust borrow checker lifetimes",
        "french cooking techniques",
        "quantum entanglement basics",
        "kubernetes pod scheduling",
        "jazz chord progressions",
        "kubernetes pod scheduling", // repeat to allow a hit
    ];
    for i in 0..1024 {
        d.put(
            &format!("{} question variant {}", topics[i % 5], i),
            serde_json::json!({"i": i}),
        );
    }
    c.bench_function("dedup_lookup_mixed_1024", |bencher| {
        bencher.iter(|| d.get(black_box("kubernetes pod scheduling question variant 500")))
    });

    // adversarial: every entry shares the template vocabulary — worst
    // case where the index degenerates to a full scan
    let d2 = Deduper::new(0.6, 1024);
    for i in 0..1024 {
        d2.put(
            &format!("prompt number {i} about topic {i} and stuff"),
            serde_json::json!({"i": i}),
        );
    }
    c.bench_function("dedup_lookup_adversarial_1024", |bencher| {
        bencher.iter(|| d2.get(black_box("prompt number 500 about topic 500 and stuff")))
    });
}

fn bench_filter(c: &mut Criterion) {
    let f = OutputFilter::new(&[
        "rm -rf".to_string(),
        "DROP TABLE".to_string(),
        "exec(".to_string(),
    ]);
    let resp = "Here is a safe response with some explanation about the code and how it works in practice for most cases.";
    c.bench_function("filter_response", |bencher| {
        bencher.iter(|| f.check(black_box(resp)))
    });
}

criterion_group!(
    benches,
    bench_blind,
    bench_feature_set,
    bench_dedup_lookup,
    bench_filter
);
criterion_main!(benches);
