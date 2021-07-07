use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

extern crate sha2;
use sha2::Sha512;

pub fn hash_to_point(data: &str) -> RistrettoPoint {
    return RistrettoPoint::hash_from_bytes::<Sha512>(data.as_bytes());
}

pub fn pedersen_commitmen(data: &[Vec<Scalar>], r: &Scalar) -> RistrettoPoint {
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