use std::ops::{Div, Sub};

use anyhow::anyhow;
use chrono::{Timelike, Utc};
use rand::SeedableRng;
use uuid::Uuid;

use rand_chacha::ChaCha20Rng;

use crate::helper::to_id;

fn seed(id: Uuid) -> [u8; 32] {
    let now = Utc::now().timestamp().div_euclid(60);
    let rnd_time = i128::MAX.div(9973).sub(now as i128);
    let mut seed: [u8; 32] = [0; 32];
    seed[..16].copy_from_slice(&rnd_time.to_be_bytes());
    seed[16..].copy_from_slice(&id.to_bytes_le());
    seed
}

fn seed_base() -> [u8; 32] {
    let now = Utc::now().timestamp().div_euclid(60);
    let time1 = i128::MAX.div(9973).sub(now as i128);
    let time2 = i128::MAX.div(99991).sub(now as i128);
    let mut seed = [0; 32];
    seed[..16].copy_from_slice(&time1.to_be_bytes());
    seed[16..].copy_from_slice(&time2.to_be_bytes());
    seed
}

// TODO: Create seed from only current time, use it for normal requests that don't have a body

pub fn get_generator(id: Uuid) -> ChaCha20Rng {
    let seed = seed(id);
    ChaCha20Rng::from_seed(seed)
}

pub fn base_generator() -> ChaCha20Rng {
    let seed = seed_base();
    ChaCha20Rng::from_seed(seed)
}

pub fn generate_uuid() -> anyhow::Result<Uuid> {
    let now = Utc::now()
        .with_second(0)
        .ok_or(anyhow!("Error changing timestamp"))?
        .timestamp();
    let id_u128 = u128::MAX.sub(now as u128).div(9980869).to_be_bytes();
    Ok(to_id(&id_u128))
}

#[cfg(test)]
mod tests {
    use rand::{
        distr::{Alphanumeric, SampleString},
        RngCore,
    };

    use super::*;
    #[test]
    fn test_semi_random() -> anyhow::Result<()> {
        for _ in 0..10 {
            let id = Uuid::new_v4(); // Generate a unique ID

            let mut rng1 = get_generator(id);
            let mut rng2 = get_generator(id);

            // Generate a large number of random numbers
            let count: usize = 100000;
            let mut results1: Vec<u32> = vec![0; count];
            let mut results2: Vec<u32> = vec![0; count];

            for i in 0..count {
                results1[i] = rng1.next_u32();
                results2[i] = rng2.next_u32();
            }

            // Check if all generated numbers are equal
            assert_eq!(results1, results2);

            let mut results1: Vec<u64> = vec![0; count];
            let mut results2: Vec<u64> = vec![0; count];

            for i in 0..count {
                results1[i] = rng1.next_u64();
                results2[i] = rng2.next_u64();
            }

            // Check if all generated numbers are equal
            assert_eq!(results1, results2);
        }

        Ok(())
    }

    #[test]
    fn test_semi_random_string() -> anyhow::Result<()> {
        for _ in 0..1 {
            let id = Uuid::new_v4(); // Generate a unique ID

            let mut rng1 = get_generator(id);
            let mut rng2 = get_generator(id);

            // Generate a large number of random numbers
            let count: usize = 100000;
            let mut results1: Vec<String> = vec![String::new(); count];
            let mut results2: Vec<String> = vec![String::new(); count];

            for i in 0..count {
                results1[i] = Alphanumeric.sample_string(&mut rng1, 128);
                results2[i] = Alphanumeric.sample_string(&mut rng2, 128);
            }

            // Check if all generated numbers are equal
            assert_eq!(results1, results2);
        }

        Ok(())
    }
}
