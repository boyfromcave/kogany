#![allow(clippy::unwrap_in_result)]

mod prop;
mod vectors;
// kogany: the Ycash Equihash switch (W1-Y2).
#[cfg(feature = "ycash")]
mod ycash;
#[cfg(not(feature = "ycash"))]
mod ycash_dormancy;
