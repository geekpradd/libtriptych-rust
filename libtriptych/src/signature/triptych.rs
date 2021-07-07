#![allow(non_snake_case)]

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use crate::util;
use rand::Rng;


#[derive(Clone, Debug)]
pub struct TriptychEllipticCurveState {
    J: RistrettoPoint,
    A: Vec<Vec<RistrettoPoint>>,
    B: Vec<Vec<RistrettoPoint>>,
    C: Vec<Vec<RistrettoPoint>>,
    D: Vec<Vec<RistrettoPoint>>,
    X: Vec<RistrettoPoint>,
    Y: Vec<RistrettoPoint>
}

#[derive(Clone, Debug)]
pub struct TryptichScalarState {
    f: Vec<Vec<Scalar>>,
    zA: Scalar,
    zC: Scalar,
    z: Scalar
}

#[derive(Clone, Debug)]
pub struct Signature {
    a: TriptychEllipticCurveState,
    z: TryptichScalarState
}

// Commitment to Zero Proof
// SARANG docs fill in, need to add here later
pub fn prove(M: Vec<RistrettoPoint>, l: usize, r: Scalar, m: i64) {
    let n = 2; // base of decomposition, Tryptich supports arbitary base, we prefer binary here

    // To-DO: RANDOM SEED NOT IMPLEMENTED YET, REFER SARANG'S REPO
    let H = util::hash_to_point("H");
    let U = util::hash_to_point("U");
    let mut rng = rand::thread_rng();

    // Error Checks are left, need to add that 

    let J = r.invert()*U;
    let rA = Scalar::random(&mut rng);
    let rB = Scalar::random(&mut rng);
    let rC = Scalar::random(&mut rng);
    let rD = Scalar::random(&mut rng); // need to add seed functionality here


;}