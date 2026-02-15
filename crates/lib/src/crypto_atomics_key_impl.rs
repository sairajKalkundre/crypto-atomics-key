use crate::generated::CryptoAtomicsKeySpec;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use craby::prelude::*;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use parking_lot::RwLock;
use rand::RngCore;
use sled;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;

pub struct CryptoAtomicsKey {
    ctx: Context,
}

// Global state using a Lock and Atomic
// --- Global State ---
static PROGRESS: AtomicU8 = AtomicU8::new(0);
static KEY_STORE: RwLock<Option<SigningKey>> = RwLock::new(None);
static DB_PATH: RwLock<Option<String>> = RwLock::new(None);
static STORED_PASSWORD: RwLock<Option<String>> = RwLock::new(None);

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedRecord {
    ciphertext: Vec<u8>,
    salt: [u8; 16],
    nonce: [u8; 12],
}

#[craby_module]
impl CryptoAtomicsKeySpec for CryptoAtomicsKey {
    fn set_credentials(&mut self, password: &str, db_path: &str) {
           *STORED_PASSWORD.write() = Some(password.to_string());
           *DB_PATH.write() = Some(db_path.to_string());
       }

       fn generate_and_store(&mut self, password: &str, db_path: &str) {
           PROGRESS.store(0, Ordering::SeqCst);
           let password = password.to_string();
           let db_path = db_path.to_string();

           // Also store for later unlock
           *STORED_PASSWORD.write() = Some(password.clone());
           *DB_PATH.write() = Some(db_path.clone());

           thread::spawn(move || {
               // 1. Generate Key
               let signing_key = SigningKey::random(&mut rand::thread_rng());
               PROGRESS.store(20, Ordering::SeqCst);

               // 2. Multi-threaded Key Stretching (Argon2)
               let mut salt = [0u8; 16];
               rand::thread_rng().fill_bytes(&mut salt);
               let argon2 = Argon2::default();
               let salt_str = SaltString::encode_b64(&salt).unwrap();

               let hash = argon2.hash_password(password.as_bytes(), &salt_str).unwrap();
               let hash_bytes = hash.hash.unwrap();
               let enc_key = Key::from_slice(&hash_bytes.as_ref()[..32]);
               PROGRESS.store(70, Ordering::SeqCst);

               // 3. Encrypt
               let mut nonce = [0u8; 12];
               rand::thread_rng().fill_bytes(&mut nonce);
               let cipher = ChaCha20Poly1305::new(enc_key);
               let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), signing_key.to_bytes().as_slice()).unwrap();

               // 4. Sled Persistence
               let db = sled::open(&db_path).expect("Failed to open Sled");
               let record = EncryptedRecord { ciphertext, salt, nonce };
               let encoded = bincode::serialize(&record).unwrap();
               db.insert("master_key", encoded).unwrap();
               db.flush().unwrap();
               drop(db);

               // 5. Finalize
               *KEY_STORE.write() = Some(signing_key);
               PROGRESS.store(100, Ordering::SeqCst);
           });
       }

    fn get_derivation_progress(&mut self) -> f64 {
        PROGRESS.load(Ordering::SeqCst) as f64
    }

    fn sign_message(&mut self, message_hex: &str) -> String {
        let lock = KEY_STORE.read();
        if let Some(key) = &*lock {
            let msg = hex::decode(message_hex).unwrap_or_default();
            let sig: Signature = key.sign(&msg);
            hex::encode(sig.to_bytes())
        } else {
            "ERROR_LOCKED".into()
        }
    }

    fn unlock_and_get_key(&mut self, _password: &str, _db_path: &str) -> Promise<String> {
            // WORKAROUND: Craby's C++ codegen captures rust::Str by reference in
            // the async thread pool lambda, so the string params are garbage by the
            // time this runs. Read from globals set by setCredentials/generateAndStore.
            let password = STORED_PASSWORD.read().clone()
                .unwrap_or_default();
            let db_path = DB_PATH.read().clone()
                .unwrap_or_default();

            if db_path.is_empty() {
                return Err(Error::new(ErrorKind::Other, "No credentials set. Call setCredentials first.").into());
            }

            let inner = || -> Result<String, Box<dyn std::error::Error>> {
                let db = sled::open(&db_path)?;
                let data = db.get("master_key")?
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "No key found. Please generate one."))?;

                let record: EncryptedRecord = bincode::deserialize(&data)?;

                let salt = SaltString::encode_b64(&record.salt).unwrap();
                let argon2 = Argon2::default();
                let hash = argon2.hash_password(password.as_bytes(), &salt)
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
                let hash_output = hash.hash.unwrap();
                let decryption_key = Key::from_slice(&hash_output.as_ref()[..32]);

                let cipher = ChaCha20Poly1305::new(decryption_key);
                let decrypted_bytes = cipher.decrypt(Nonce::from_slice(&record.nonce), record.ciphertext.as_slice())
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

                let signing_key = SigningKey::from_slice(&decrypted_bytes)
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

                let private_key_hex = hex::encode(signing_key.to_bytes());
                *KEY_STORE.write() = Some(signing_key);

                Ok(private_key_hex)
            };

            match inner() {
                Ok(val) => Ok(val),
                Err(e) => Err(Error::new(ErrorKind::Other, e.to_string()).into()),
            }
        }

    fn get_active_key_hex(&mut self) -> String {
        let lock = KEY_STORE.read();
        if let Some(key) = &*lock {
            hex::encode(key.to_bytes())
        } else {
            String::new()
        }
    }

}
