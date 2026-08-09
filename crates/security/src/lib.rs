use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{thread_rng, RngCore};

pub fn encrypt_packet(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;

    let mut packet = nonce_bytes.to_vec();
    packet.append(&mut ciphertext);
    Ok(packet)
}

pub fn decrypt_packet(key: &[u8; 32], packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.len() < 12 {
        return Err("Invalid packet length: missing nonce".to_string());
    }

    let (nonce_bytes, ciphertext) = packet.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_success() {
        let key = [7u8; 32];
        let plaintext = b"Project Chronos deterministic packet data";

        let ciphertext = encrypt_packet(&key, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_packet(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decryption_tamper_failure() {
        let key = [9u8; 32];
        let plaintext = b"Sensitive trade details";

        let mut ciphertext = encrypt_packet(&key, plaintext).unwrap();

        // Tamper with the ciphertext (flip one byte after the nonce)
        ciphertext[15] ^= 0xFF;

        let result = decrypt_packet(&key, &ciphertext);
        assert!(result.is_err()); // Poly1305 authentication tag check must fail
    }
}
