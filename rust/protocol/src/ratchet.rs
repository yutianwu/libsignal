//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use std::io::Read;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::{CryptoRng, Rng};
use sha2::{Sha512, Digest};
use curve25519_dalek::ristretto::CompressedRistretto;

use crate::protocol::{CIPHERTEXT_MESSAGE_CURRENT_VERSION, CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION};
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, PrivateKey, PublicKey, SignalProtocolError};

pub(crate) use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};

fn derive_keys(has_kyber: bool, secret_input: &[u8]) -> (RootKey, ChainKey) {
    let label = if has_kyber {
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".as_slice()
    } else {
        b"WhisperText".as_slice()
    };
    derive_keys_with_label(label, secret_input)
}

fn message_version(has_kyber: bool) -> u8 {
    if has_kyber {
        CIPHERTEXT_MESSAGE_CURRENT_VERSION
    } else {
        CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION
    }
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
}

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    let ephemeral_key = KeyPair::generate(&mut csprng);

    let ephemeral_private_key = ephemeral_key.private_key.calculate_compressed_edwards_pubkey()?;

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        let r = ephemeral_key.private_key;
        let opk_seed = their_one_time_prekey;

        let ed_pub_key = CompressedEdwardsY::from_slice(their_one_time_prekey.public_key_bytes()?).unwrap().decompress().unwrap();

        // 计算 OPK_B
        let bytes = opk_seed.public_key_bytes()?;
        println!("Step 2: Got opk_seed public key bytes: {:?}", bytes);

        // 创建正确格式的公钥
        let m_pub_key = PublicKey::from_djb_public_key_bytes(ed_pub_key.to_montgomery().to_bytes().as_slice())?;
        let shared_secret = r.calculate_agreement(&m_pub_key)?;
        println!("Alice Step 3: Calculated shared secret: {:?}", shared_secret);
        println!("Alice Step 3.1: Using ephemeral private key: {:?}", ephemeral_key.private_key.serialize());
        println!("Alice Step 3.2: Using opk_seed public key: {:?}", opk_seed.public_key_bytes()?);

        let mut hasher = Sha512::new();
        hasher.update(&shared_secret);
        let hash_result = hasher.clone().finalize();
        println!("Alice Step 4: Hasher result: {:?}", hash_result);
        let hash_scalar = Scalar::from_hash(hasher);
        println!("Alice Step 4.1: Hash scalar bytes: {:?}", hash_scalar.to_bytes());
        println!("Step 4: Generated hash scalar");

        // 使用 RISTRETTO_BASEPOINT_POINT 和标量相乘来创建点
        let seed_point = CompressedRistretto::from_slice(&opk_seed.public_key_bytes()?)
            .map_err(|_| SignalProtocolError::InvalidArgument("Invalid point bytes".to_string()))?
            .decompress()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("Failed to decompress point".to_string()))?;
        println!("Step 5.2: Successfully created seed point");

        let opk_b_alice = (hash_scalar * RISTRETTO_BASEPOINT_POINT) + ed_pub_key.to_montgomery();
        println!("Step 6: Calculated opk_b_alice");

        // 使用相同的方式创建公钥
        let opk_b_pk_alice = PublicKey::from_djb_public_key_bytes(opk_b_alice.compress().as_bytes())?;
        println!("Step 7: Created Alice's public key: {:?}", opk_b_pk_alice.public_key_bytes()?);

        // 将 DjbPublicKey 转换回 RistrettoPoint 并打印
        let alice_point = CompressedRistretto::from_slice(&opk_b_pk_alice.public_key_bytes()?)
            .and_then(|compressed| Ok(compressed.decompress().unwrap()))
            .expect("Valid public key");
        println!("Step 7.1: Converted back to RistrettoPoint: {:?}", alice_point.compress().as_bytes());

        println!("Step 8: Deserialized Alice's public key");

        // Alice 端计算 agreement
        let alice_agreement = our_base_private_key.calculate_agreement(&opk_b_pk_alice)?;
        println!("Alice Agreement: {:?}", alice_agreement);
        secrets.extend_from_slice(&alice_agreement);
    }

    let kyber_ciphertext = parameters.their_kyber_pre_key().map(|kyber_public| {
        let (ss, ct) = kyber_public.encapsulate();
        secrets.extend_from_slice(ss.as_ref());
        ct
    });
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let (root_key, chain_key) = derive_keys(has_kyber, &secrets);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let mut session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    let pub_key = PublicKey::from_djb_public_key_bytes(&ephemeral_private_key.to_bytes())?;
    session.set_ephemeral_derivation_key(&pub_key);

    if let Some(kyber_ciphertext) = kyber_ciphertext {
        session.set_kyber_ciphertext(kyber_ciphertext);
    }

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        if let Some(ephemeral_key) = parameters.ephemeral_derivation_key() {
            let opk_seed_sk = our_one_time_pre_key_pair.private_key;
            println!("Bob Step 1: Got one_time_pre_key private key");

            let ephemeral_public = PublicKey::from_djb_public_key_bytes(ephemeral_key.public_key_bytes()?)?;
            println!("Bob Step 2: Got ephemeral public key: {:?}", ephemeral_key.public_key_bytes()?);

            // 1. Calculate OPK_seed_sk * R (使用与Alice相同的方式计算shared secret)
            let shared_secret = opk_seed_sk.calculate_agreement(&ephemeral_public)?;
            println!("Bob Step 3: Calculated shared secret: {:?}", shared_secret);
            println!("Bob Step 3.1: Using opk_seed_sk private key: {:?}", opk_seed_sk.serialize());
            println!("Bob Step 3.2: Using ephemeral public key: {:?}", ephemeral_public.public_key_bytes()?);

            // 2. Hash the shared secret (与Alice使用相同的哈希方法)
            let mut hasher = Sha512::new();
            hasher.update(&shared_secret);
            let hash_result = hasher.clone().finalize();
            println!("Bob Step 4: Hasher result: {:?}", hash_result);
            let hash_scalar = Scalar::from_hash(hasher);
            println!("Bob Step 4.1: Hash scalar bytes: {:?}", hash_scalar.to_bytes());
            println!("Bob Step 4: Generated hash scalar");

            // 3. 使用相同的seed_point计算
            let seed_scalar = Scalar::from_bytes_mod_order(opk_seed_sk.serialize()[..32].try_into().unwrap());
            let seed_point = seed_scalar * RISTRETTO_BASEPOINT_POINT;
            println!("Bob Step 6: Created seed point");

            // 4. 计算公钥点
            let opk_b_bob = (hash_scalar  + seed_scalar) * RISTRETTO_BASEPOINT_POINT;
            let opk_b_pk_bob = PublicKey::from_djb_public_key_bytes(opk_b_bob.compress().as_bytes())?;
            println!("Bob Step 7: Generated Bob's public key: {:?}", opk_b_pk_bob.public_key_bytes()?);

            // 将 DjbPublicKey 转换回 RistrettoPoint 并打印
            let bob_point = CompressedRistretto::from_slice(&opk_b_pk_bob.public_key_bytes()?)
                .and_then(|compressed| Ok(compressed.decompress().unwrap()))
                .expect("Valid public key");
            println!("Bob Step 7.1: Converted back to RistrettoPoint: {:?}", bob_point.compress().as_bytes());

            // 5. 计算对应的私钥标量
            let opk_seed_sk_bytes = opk_seed_sk.serialize();
            println!("Bob Step 8: Original private key bytes length: {}", opk_seed_sk_bytes.len());
            let opk_seed_sk_scalar = Scalar::from_bytes_mod_order(opk_seed_sk_bytes[..32].try_into().unwrap());
            // 使用与 Alice 相同的方式计算私钥
            let opk_b_sk_scalar = hash_scalar + opk_seed_sk_scalar;
            println!("Bob Step 9: Generated private key scalar");

            // 6. 将私钥标量转换为私钥
            let mut private_key_bytes = [0u8; 32];
            private_key_bytes.copy_from_slice(&opk_b_sk_scalar.to_bytes());
            let opk_b_sk_bob = PrivateKey::deserialize(&private_key_bytes)?;
            println!("Bob Step 10: Generated Bob's private key");

            // 7. 使用 opk_b_sk_bob 计算共享密钥
            let agreement = opk_b_sk_bob.calculate_agreement(parameters.their_base_key())?;
            println!("Bob Agreement: {:?}", agreement);
            println!("Bob Step 12: Agreement length: {}", agreement.len());

            secrets.extend_from_slice(&agreement);
            println!("Bob Step 13: Extended secrets with agreement");
            println!("Bob Step 14: Current secrets length: {}", secrets.len());
        } else {
            let agreement = our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?;
            println!("Bob Alt Path: Using direct agreement, length: {}", agreement.len());
            secrets.extend_from_slice(&agreement);
        }
    }


    match (
        parameters.our_kyber_pre_key_pair(),
        parameters.their_kyber_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            let ss = key_pair.secret_key.decapsulate(ciphertext)?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (None, None) => (), // Alice does not support kyber prekeys
        _ => {
            panic!("Either both or none of the kyber key pair and ciphertext can be provided")
        }
    }
    let has_kyber = parameters.our_kyber_pre_key_pair().is_some();

    let (root_key, chain_key) = derive_keys(has_kyber, &secrets);

    let session = SessionState::new(
        message_version(has_kyber),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_opk_calculation_matches() -> Result<()> {
        let mut rng = OsRng;

        // 生成测试密钥对
        let opk_seed_pair = KeyPair::generate(&mut rng);
        let r_pair = KeyPair::generate(&mut rng);

        println!("Step 1: Generated key pairs");

        // Alice 端计算
        let r = r_pair.private_key;
        let opk_seed = opk_seed_pair.public_key;

        // 使用 ephemeral 私钥和 one-time prekey 公钥计算 shared_secret
        let shared_secret = r.calculate_agreement(&opk_seed)?;
        println!("Alice Step 3: Calculated shared secret: {:?}", shared_secret);
        println!("Alice Step 3.1: Using r_pair public key: {:?}", r_pair.public_key.public_key_bytes()?);
        println!("Alice Step 3.2: Using opk_seed public key: {:?}", opk_seed.public_key_bytes()?);

        let mut hasher = Sha512::new();
        hasher.update(&shared_secret);
        let hash_result = hasher.clone().finalize();
        println!("Alice Step 4: Hasher result: {:?}", hash_result);
        let hash_scalar = Scalar::from_hash(hasher);
        println!("Alice Step 4.1: Hash scalar bytes: {:?}", hash_scalar.to_bytes());
        println!("Step 4: Generated hash scalar");

        // 使用 public_key_bytes 创建 RistrettoPoint
        let seed_bytes = opk_seed.public_key_bytes()?;
        println!("Step 4.1: Got seed bytes: {:?}", seed_bytes);

        // 使用 RISTRETTO_BASEPOINT_POINT 和标量相乘来创建点
        let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();
        let seed_scalar = Scalar::from_bytes_mod_order(seed_array);
        let seed_point = seed_scalar * RISTRETTO_BASEPOINT_POINT;
        println!("Step 5: Created seed point");

        let opk_b_alice = (hash_scalar * RISTRETTO_BASEPOINT_POINT) + seed_point;
        println!("Step 6: Calculated opk_b_alice");

        // 使用相同的方式创建公钥
        let opk_b_pk_alice = PublicKey::from_djb_public_key_bytes(opk_b_alice.compress().as_bytes())?;
        println!("Step 7: Created Alice's public key: {:?}", opk_b_pk_alice.public_key_bytes()?);

        // 将 DjbPublicKey 转换回 RistrettoPoint 并打印
        let alice_point = CompressedRistretto::from_slice(&opk_b_pk_alice.public_key_bytes()?)
            .and_then(|compressed| Ok(compressed.decompress().unwrap()))
            .expect("Valid public key");
        println!("Step 7.1: Converted back to RistrettoPoint: {:?}", alice_point.compress().as_bytes());

        println!("Step 8: Deserialized Alice's public key");

        // Bob 端计算
        let opk_seed_sk = opk_seed_pair.private_key;
        let ephemeral_public = r_pair.public_key;

        // 使用 one-time prekey 私钥和 ephemeral 公钥计算 shared_secret
        let shared_secret = opk_seed_sk.calculate_agreement(&ephemeral_public)?;
        println!("Bob Step 3: Calculated shared secret: {:?}", shared_secret);
        println!("Bob Step 3.1: Using opk_seed_sk private key: {:?}", opk_seed_sk.serialize());
        println!("Bob Step 3.2: Using ephemeral public key: {:?}", ephemeral_public.public_key_bytes()?);

        // 2. Hash the shared secret (与Alice使用相同的哈希方法)
        let mut hasher = Sha512::new();
        hasher.update(&shared_secret);
        let hash_result = hasher.clone().finalize();
        println!("Bob Step 4: Hasher result: {:?}", hash_result);
        let hash_scalar = Scalar::from_hash(hasher);
        println!("Bob Step 4.1: Hash scalar bytes: {:?}", hash_scalar.to_bytes());
        println!("Bob Step 4: Generated hash scalar");

        // 3. 使用相同的seed_point计算
        let seed_bytes = opk_seed_pair.public_key.public_key_bytes()?;
        let seed_array: [u8; 32] = seed_bytes.try_into().unwrap();
        let seed_scalar = Scalar::from_bytes_mod_order(seed_array);
        let seed_point = seed_scalar * RISTRETTO_BASEPOINT_POINT;

        // 4. 计算公钥点
        let opk_b_bob = (hash_scalar * RISTRETTO_BASEPOINT_POINT) + seed_point;
        let opk_b_pk_bob = PublicKey::from_djb_public_key_bytes(opk_b_bob.compress().as_bytes())?;
        println!("Bob Step 7: Generated Bob's public key: {:?}", opk_b_pk_bob.public_key_bytes()?);

        // 将 DjbPublicKey 转换回 RistrettoPoint 并打印
        let bob_point = CompressedRistretto::from_slice(&opk_b_pk_bob.public_key_bytes()?)
            .and_then(|compressed| Ok(compressed.decompress().unwrap()))
            .expect("Valid public key");
        println!("Bob Step 7.1: Converted back to RistrettoPoint: {:?}", bob_point.compress().as_bytes());

        // 5. 计算对应的私钥标量
        let opk_seed_sk_bytes = opk_seed_sk.serialize();
        println!("Bob Step 8: Original private key bytes length: {}", opk_seed_sk_bytes.len());
        let opk_seed_sk_scalar = Scalar::from_bytes_mod_order(opk_seed_sk_bytes[..32].try_into().unwrap());
        // 使用与 Alice 相同的方式计算私钥
        let opk_b_sk_scalar = hash_scalar + opk_seed_sk_scalar;
        println!("Bob Step 9: Generated private key scalar");

        // 6. 将私钥标量转换为私钥
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&opk_b_sk_scalar.to_bytes());
        let opk_b_sk_bob = PrivateKey::deserialize(&private_key_bytes)?;
        println!("Bob Step 10: Generated Bob's private key");

        // 7. 使用 opk_b_sk_bob 计算共享密钥
        let base_key = KeyPair::generate(&mut rng);
        let agreement = opk_b_sk_bob.calculate_agreement(&base_key.public_key)?;
        println!("Bob Agreement: {:?}", agreement);
        println!("Bob Step 12: Agreement length: {}", agreement.len());

        // 计算 Alice 端的 agreement
        let alice_agreement = base_key.private_key.calculate_agreement(&opk_b_pk_alice)?;
        println!("Alice Agreement with base key: {:?}", alice_agreement);

        assert_eq!(
            agreement,
            alice_agreement,
            "Alice 和 Bob 计算的 agreement 应该相同"
        );

        // 验证 Alice 和 Bob 计算的结果是否匹配
        let alice_bytes = opk_b_pk_alice.public_key_bytes()?;
        let bob_bytes = opk_b_pk_bob.public_key_bytes()?;
        println!("Alice's public key bytes: {:?}", alice_bytes);
        println!("Bob's public key bytes: {:?}", bob_bytes);

        assert_eq!(
            alice_bytes,
            bob_bytes,
            "Alice 和 Bob 计算的 OPK_B 应该相同"
        );

        // 验证密钥对是否正确配对
        let agreement1 = opk_b_sk_bob.calculate_agreement(&opk_b_pk_alice)?;
        let agreement2 = opk_b_sk_bob.calculate_agreement(&opk_b_pk_bob)?;

        assert_eq!(
            agreement1,
            agreement2,
            "Bob 的私钥应该能够与 Alice 的公钥正确协商"
        );

        Ok(())
    }
}
