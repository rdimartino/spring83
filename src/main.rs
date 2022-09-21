use chrono::prelude::*;
use chrono::{Months, NaiveDate, Utc};
use ed25519_dalek::{Keypair, PublicKey};
use hex::ToHex;
use rand::rngs::OsRng;

fn key_suffix() -> String {
    let today = Utc::today();
    let valid_until = NaiveDate::from_ymd(today.year(), today.month(), 1)
        .checked_add_months(Months::new(24))
        .unwrap();
    format!(
        "83e{:02}{:02}",
        valid_until.month(),
        valid_until.year() % 100
    )
}

#[test]
fn test_key_suffix() {
    assert_eq!("83e0924", key_suffix())
}

fn is_valid(key: &PublicKey) -> bool {
    let bytes = key.as_bytes();
    let s = bytes.encode_hex::<String>();
    s.ends_with(&key_suffix())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::PUBLIC_KEY_LENGTH;
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
    let mut csprng = OsRng {};
    let mut key = None;
    while key.is_none() {
        let keypair: Keypair = Keypair::generate(&mut csprng);
        if is_valid(&keypair.public) {
            key = Some(keypair)
        }
    }
    println!("{:?}", key);
}
