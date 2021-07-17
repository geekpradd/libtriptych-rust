#![allow(non_snake_case)]

use criterion::{criterion_group, criterion_main, Criterion};
use libtriptych::signature::triptych;

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

pub fn create_proof_benchmark_128(c: &mut Criterion) {
    let size = 128;
    let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); size];
    let mut x: Scalar = Scalar::one();
    let index = 32;

    for i in 0..size {
        let (sk, pk) = triptych::KeyGen();
        R[i] = pk;

        if i == index {
            x = sk;
        }
    }
    let M = "Benchmarking String on which signature is being created";

    c.bench_function("create_proof_benchmark_128", |b| b.iter(|| triptych::Sign(&x, &M, &R) ));
}

pub fn verify_proof_benchmark_128(c: &mut Criterion) {
    let size = 128;
    let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); size];
    let mut x: Scalar = Scalar::one();
    let index = 39;

    for i in 0..size {
        let (sk, pk) = triptych::KeyGen();
        R[i] = pk;

        if i == index {
            x = sk;
        }
    }
    let M = "Benchmarking Verification Time";

    let sgn = triptych::Sign(&x, &M, &R);


    c.bench_function("verify_proof_benchmark_128", |b| b.iter(|| {
        let result = triptych::Verify(&sgn, &M, &R);
        assert!(result.is_ok());
    }));
}

pub fn create_proof_benchmark_256(c: &mut Criterion) {
    let size = 256;
    let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); size];
    let mut x: Scalar = Scalar::one();
    let index = 32;

    for i in 0..size {
        let (sk, pk) = triptych::KeyGen();
        R[i] = pk;

        if i == index {
            x = sk;
        }
    }
    let M = "Benchmarking String on which signature is being created";

    c.bench_function("create_proof_benchmark_256", |b| b.iter(|| triptych::Sign(&x, &M, &R) ));
}

pub fn verify_proof_benchmark_256(c: &mut Criterion) {
    let size = 256;
    let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); size];
    let mut x: Scalar = Scalar::one();
    let index = 39;

    for i in 0..size {
        let (sk, pk) = triptych::KeyGen();
        R[i] = pk;

        if i == index {
            x = sk;
        }
    }
    let M = "Benchmarking Verification Time";

    let sgn = triptych::Sign(&x, &M, &R);


    c.bench_function("verify_proof_benchmark_256", |b| b.iter(|| {
        let result = triptych::Verify(&sgn, &M, &R);
        assert!(result.is_ok());
    }));
}


criterion_group!{
    name = triptych_signature_test;
    config = Criterion::default().sample_size(10);
    targets = 
        create_proof_benchmark_128,
        verify_proof_benchmark_128,
        create_proof_benchmark_256,
        verify_proof_benchmark_256,
}

criterion_main!(triptych_signature_test);