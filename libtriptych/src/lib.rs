extern crate curve25519_dalek;
extern crate sha2;
extern crate rand;
pub mod signature;
pub mod util;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    TriptychError
}