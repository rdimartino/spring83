use chrono::prelude::*;
use chrono::{Months, NaiveDate, Utc};
use ed25519_dalek::{Keypair, PublicKey, PUBLIC_KEY_LENGTH};
use hex::ToHex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc};
use std::thread;

lazy_static::lazy_static! {
    static ref SUFFIX: Vec<u8> = {
        let (month, year) = valid_until();
        vec![0x3e, month, year]
    };
}

fn valid_until() -> (u8, u8) {
    let today = Utc::today();
    let future = NaiveDate::from_ymd(today.year(), today.month(), 1)
        .checked_add_months(Months::new(24))
        .unwrap();
    (
        future.month() as u8,
        (future.year() / 10 % 10 * 16 + future.year() % 10) as u8,
    )
}

#[test]
fn test_valid_until() {
    assert_eq!((0x09, 0x24), valid_until())
}

fn is_valid(key: &PublicKey) -> bool {
    let bytes = key.as_bytes();
    let suffix = &bytes[PUBLIC_KEY_LENGTH - 3..];
    suffix == &SUFFIX[..] && bytes[PUBLIC_KEY_LENGTH - 4] % 16 == 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_is_valid() {
        // originally 83e0623
        let good_key_bytes = <[u8; PUBLIC_KEY_LENGTH]>::from_hex(
            "ca93846ae61903a862d44727c16fed4b80c0522cab5e5b8b54763068b83e0924",
        )
        .unwrap();
        let good_key = PublicKey::from_bytes(&good_key_bytes).unwrap();
        assert_eq!(is_valid(&good_key), true);
        // infernal key
        let bad_key_bytes = <[u8; PUBLIC_KEY_LENGTH]>::from_hex(
            "d17eef211f510479ee6696495a2589f7e9fb055c2576749747d93444883e0123",
        )
        .unwrap();
        let bad_key = PublicKey::from_bytes(&bad_key_bytes).unwrap();
        assert_eq!(is_valid(&bad_key), false);
    }
}

fn main() {
    let found = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel();
    let mut children = vec![];
    for _ in 0..10 {
        let (stop, tx) = (Arc::clone(&found), tx.clone());
        children.push(thread::spawn(move || {
            let mut rng = rand::thread_rng();
            while !stop.load(Ordering::Relaxed) {
                let keypair: Keypair = Keypair::generate(&mut rng);
                if is_valid(&keypair.public) {
                    tx.send(keypair).unwrap();
                }
            }
        }));
    }

    let key = rx.recv().unwrap();
    found.store(false, Ordering::Relaxed);
    _ = children.into_iter().map(|c| c.join().unwrap());
    println!("secret: {}\npublic: {}", key.secret.encode_hex::<String>(), key.public.encode_hex::<String>());
}
