#![allow(non_snake_case)]

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::util;
use rand::Rng;
use std::convert::TryInto;

pub fn pad(n: &usize, m: &usize) -> Vec<usize> {
    let mut s = format!("{:b}", n); // this is using base 2, for other bases this will change
    
    if s.chars().count() < *m{
        s = format!("{}{}", "0".repeat(*m - s.chars().count()), s);
    }

    return s.chars().rev().map(|i| i as usize - '0' as usize).collect::<Vec<usize>>();
}

pub fn convolve(x: &[Scalar], y: &[Scalar]) -> Vec<Scalar> {
    let mut r: Vec<Scalar> = vec![Scalar::zero(); x.len()+1];
    for i in 0..x.len(){
        for j in 0..y.len(){
            r[i+j] += x[i]*y[i];
        }
    }

    return r;
}
#[derive(Clone, Debug)]
pub struct TriptychEllipticCurveState {
    J: RistrettoPoint,
    A: RistrettoPoint,
    B: RistrettoPoint,
    C: RistrettoPoint,
    D: RistrettoPoint,
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
pub fn prove(M: Vec<RistrettoPoint>, l: usize, r: Scalar, m: usize) {
    let n: usize = 2; // base of decomposition, Tryptich supports arbitary base, we prefer binary here

    // To-DO: RANDOM SEED NOT IMPLEMENTED YET, REFER SARANG'S REPO
    let H = util::hash_to_point("H");
    let U = util::hash_to_point("U");

    let G = util::hash_to_point("G"); 
    // In Risretto Curve, all POINTS are generators. G choice is arbitary here
    let mut rng = rand::thread_rng();

    // Error Checks are left, need to add that 
    let J = r.invert()*U;
    let rA = Scalar::random(&mut rng);
    let rB = Scalar::random(&mut rng);
    let rC = Scalar::random(&mut rng);
    let rD = Scalar::random(&mut rng); // need to add seed functionality here

    let mut a = (0..m).map(|_| (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<Scalar>>()).collect::<Vec<Vec<Scalar>>>();

    for entry in &mut a {
        entry[0] = (1..n).fold(Scalar::zero(), |acc, x|{
            acc - entry[x]
        });
    }

    let mut A = util::pedersen_commitment(&a, &rA);
    let mut s = pad(&l, &m); // this is for base 2

    let mut b = (0..m).map(|j| (0..n).map(|i| util::delta(&s[j], &i)).collect::<Vec<Scalar>>()).collect::<Vec<Vec<Scalar>>>();

    let mut B = util::pedersen_commitment(&b, &rB);

    let mut c = (0..m).map(|j| (0..n).map(|i| a[j][i]*(Scalar::one() - b[j][i] - b[j][i])).collect::<Vec<Scalar>>()).collect::<Vec<Vec<Scalar>>>();

    let mut C = util::pedersen_commitment(&c, &rC);

    // the minus may not work here, check later
    let mut d = (0..m).map(|j| (0..n).map(|i| -a[j][i]*a[j][i]).collect::<Vec<Scalar>>()).collect::<Vec<Vec<Scalar>>>();

    let mut D = util::pedersen_commitment(&d, &rD);

    let m_u32: u32 = m.try_into().unwrap();
    let N = usize::pow(n, m_u32); // we have n = 2, N = 2**m = len(M)

    let mut p = (0..N).map(|_| vec![]).collect::<Vec<Vec<Scalar>>>();

    for k in 0..N {
        let binary_k = pad(&k, &m); // This can be sped up by gray codes, will have to change after bench
        p[k] = vec![a[0][binary_k[0]], util::delta(&s[0], &binary_k[0])];

        for j in 1..m {
            p[k] = convolve(&p[k], &vec![a[j][binary_k[j]], util::delta(&s[j], &binary_k[j])]);
        }
    }

    let mut X = vec![RistrettoPoint::identity(); m];
    

    let mut rho = (0..m).map(|_| Scalar::random(&mut rng)).collect::<Vec<Scalar>>();

    let mut Y = (0..m).map(|i| rho[i]*J).collect::<Vec<RistrettoPoint>>();

    let mut X = (0..m).map(|j| (0..N).fold(rho[j]*G, |acc, k|{
                                            acc + p[k][j]*M[k]
                                        })).collect::<Vec<RistrettoPoint>>();


    let state: TriptychEllipticCurveState = TriptychEllipticCurveState {
        J, A, B, C, D, X, Y
    };
    //  need to hash here and then output can be created (scalar state)
    
;}