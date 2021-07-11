use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;

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
            r[i+j] += x[i]*y[j];
        }
    }

    return r;
}

pub fn hash_to_point(data: &str) -> RistrettoPoint {
    return RistrettoPoint::hash_from_bytes::<Sha512>(data.as_bytes());
}

pub fn pedersen_commitment(data: &[Vec<Scalar>], r: &Scalar) -> RistrettoPoint {
    let mut com = r * hash_to_point("H");


    for (i, vector) in data.iter().enumerate(){
        for (j, entry) in vector.iter().enumerate() {
            let hash_digest = format!("G{}{}", i, j);
            let point = hash_to_point(&hash_digest);
            com = com + entry*point;
        }
    }

    return com;
}

pub fn delta(value: &usize, i: &usize) -> Scalar {
  
    if *i == *value {
        return Scalar::one();
    }
    else {
        return Scalar::zero();
    }
}

pub fn power(base_: &Scalar, exp_: &usize) -> Scalar {
    let mut answer = Scalar::one();
    let mut exp = exp_.clone();
    let mut base = base_.clone();
    while exp > 0 {
        if exp % 2 == 1 {
            answer = answer*base;
            exp = exp-1;
        }
        else {
            exp = exp/2;
            base = base*base;
        }

    }

    return answer;
}
