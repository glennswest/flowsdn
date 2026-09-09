//! Identity primitives from identity specification §§4.4–4.5.
//! Numeric validation does not allocate identities or validate their labels.
#![no_std]

extern crate alloc;

pub mod labels;
pub mod numeric;
pub use numeric::*;

pub mod cidr;
#[cfg(feature = "filter")]
pub mod filter;
