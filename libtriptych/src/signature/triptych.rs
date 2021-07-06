#![allow(non_snake_case)]

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;


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
