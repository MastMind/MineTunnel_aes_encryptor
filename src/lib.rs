use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use cmac::{Cmac, Mac as CmacMac};
use hmac::{Hmac, NewMac as HmacNewMac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::os::raw::{c_void};
use std::slice;




enum EncryptorType {
    // EncryptorUnknown = 0,
    EncryptorSymmetric = 1,
    // EncryptorAsymmetric = 2
}

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type CmacAes128 = Cmac<Aes128>;
type HmacSha256 = Hmac<Sha256>;

const CMAC_TAG_LEN: usize = 16; // CMAC-AES128 tag size (one AES block)
const HMAC_TAG_LEN: usize = 32; // HMAC-SHA256 tag size

#[derive(Clone)]
struct AESKey {
    key: [u8; 16],
    iv: [u8; 16],
    cmac: [u8; 16],
    hmac: Vec<u8>
}

#[derive(Serialize, Deserialize)]
struct KeyParams {
    key: String,
    iv: Option<String>,
    cmac: Option<String>,
    hmac: Option<String>
}

#[unsafe(no_mangle)]
pub extern "C" fn create_instance(_json_str: *const u8) -> *mut c_void {
    let c_str = unsafe { std::ffi::CStr::from_ptr(_json_str as *const i8) };
    let json_data = c_str.to_str().unwrap_or("");

    let mut instance = AESKey {
        key: [0u8; 16],
        iv:  [0u8; 16],
        cmac: [0u8; 16],
        hmac: Vec::new()
    };

    match serde_json::from_str::<KeyParams>(json_data) {
        Ok(params) => {
            if params.key.len() == 32 {
                let decoded_bytes = match hex::decode(&params.key) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return std::ptr::null_mut();
                    }
                };

                instance.key = decoded_bytes.as_slice().try_into().unwrap();
            } else {
                return std::ptr::null_mut()
            }

            if let Some(ref iv_hex) = params.iv {
                if iv_hex.len() == 32 {
                    let decoded_bytes = match hex::decode(&iv_hex) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return std::ptr::null_mut()
                        }
                    };
                    instance.iv = decoded_bytes.as_slice().try_into().unwrap();
                }
            }

            if let Some(ref cmac_hex) = params.cmac {
                if cmac_hex.len() == 32 {
                    let decoded_bytes = match hex::decode(&cmac_hex) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return std::ptr::null_mut()
                        }
                    };
                    instance.cmac = decoded_bytes.as_slice().try_into().unwrap();
                }
            }

            if let Some(ref hmac_hex) = params.hmac {
                if hmac_hex.len() >= 64 {
                    let decoded_bytes = match hex::decode(&hmac_hex) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return std::ptr::null_mut()
                        }
                    };
                    instance.hmac = decoded_bytes;
                }
            }

            return Box::into_raw(Box::new(instance)) as *mut c_void;
        }
        Err(_) => return std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn encrypt(_instance: *mut c_void, _buf: *mut u8, _size: u32) -> u32 {
    if _instance.is_null() {
        return 0;
    }

    let instance = unsafe {
        &mut *(_instance as *mut AESKey)
    };

    let cipher = Aes128Cbc::new_from_slices(&instance.key, &instance.iv).unwrap();
    let buf_ref: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(_buf, (_size as usize) + 16 
            + CMAC_TAG_LEN + HMAC_TAG_LEN)
    };

    let ciphertext = match cipher.encrypt(buf_ref, _size as usize) {
        Ok(ct) => ct,
        Err(e) => {
            eprintln!("encrypt error: {:?}", e);
            return 0;
        }
    };

    let mut ciphertext_len = ciphertext.len() as usize;
    let ciphertext_only_len = ciphertext_len;
    //calculte cmac if cmac key is not empty
    if instance.cmac != [0u8; 16] {
        let mut cmac_mac = CmacAes128::new_from_slice(&instance.cmac).
            unwrap();
        cmac_mac.update(&buf_ref[..ciphertext_only_len]);
        let cmac_tag = cmac_mac.finalize().into_bytes();
        buf_ref[ciphertext_len..ciphertext_len + CMAC_TAG_LEN].copy_from_slice(
            &cmac_tag);
        ciphertext_len += CMAC_TAG_LEN;
    }

    //calculate hmac if hmac is not empty
    if !instance.hmac.is_empty() {
        let mut hmac_mac = HmacSha256::new_from_slice(&instance.hmac).
            unwrap();
        hmac_mac.update(&buf_ref[..ciphertext_only_len]);
        let hmac_tag = hmac_mac.finalize().into_bytes();
        buf_ref[ciphertext_len..ciphertext_len + HMAC_TAG_LEN].copy_from_slice(
            &hmac_tag);
        ciphertext_len += HMAC_TAG_LEN;
    }

    return ciphertext_len as u32;
}

#[unsafe(no_mangle)]
pub extern "C" fn decrypt(_instance: *mut c_void, _buf: *mut u8, _size: u32) -> u32 {
    if _instance.is_null() {
        return 0;
    }

    let instance = unsafe {
        &mut *(_instance as *mut AESKey)
    };

    let cipher = Aes128Cbc::new_from_slices(&instance.key, &instance.iv).unwrap();
    let buf_ref: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(_buf, _size as usize)
    };

    let mut ciphertext_len = _size as usize;
    if instance.cmac != [0u8; 16] {
        ciphertext_len -= CMAC_TAG_LEN;
    }

    if !instance.hmac.is_empty() {
        ciphertext_len -= HMAC_TAG_LEN;
    }

    //checking cmac
    if instance.cmac != [0u8; 16] {
        let mut cmac_mac = CmacAes128::new_from_slice(&instance.cmac).unwrap();
        cmac_mac.update(&buf_ref[..ciphertext_len]);
        if cmac_mac.verify(&buf_ref[ciphertext_len..ciphertext_len + CMAC_TAG_LEN]).is_err() {
            return 0;
        }
    }

    //checking cmac
    if !instance.hmac.is_empty() {
        let hmac_start = ciphertext_len + if instance.cmac != [0u8; 16] { CMAC_TAG_LEN } else { 0 };
        let mut hmac_mac = HmacSha256::new_from_slice(&instance.hmac).unwrap();
        hmac_mac.update(&buf_ref[..ciphertext_len]);
        if hmac_mac.verify(&buf_ref[hmac_start..hmac_start + HMAC_TAG_LEN]).is_err() {
            return 0;
        }
    }

    //pass cyphertext only without tags
    let buf_ct: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(_buf, ciphertext_len)
    };
    let decryptedtext = cipher.decrypt(buf_ct).unwrap_or_else(|_e| {
        return &[];
    });
    return decryptedtext.len() as u32;
}

#[unsafe(no_mangle)]
pub fn get_type() -> i32 {
    return EncryptorType::EncryptorSymmetric as i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn destroy_instance(_instance: *mut c_void) {
    if _instance.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(_instance as *mut AESKey));
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const KEY_HEX:  &str = "00112233445566778899aabbccddeeff";
    const IV_HEX:   &str = "00000000000000000000000000000000";
    const CMAC_HEX: &str = "aabbccddeeff00112233445566778899";
    const HMAC_HEX: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const BOTH_TAG_LEN: usize = CMAC_TAG_LEN + HMAC_TAG_LEN;

    fn make_test_json() -> CString {
        CString::new(
            r#"{
                "key": "00112233445566778899AABBCCDDEEFF",
                "iv":  "00000000000000000000000000000000"
            }"#,
        )
        .unwrap()
    }

        fn roundtrip(json_str: &str, tag_len: usize) {
        let json     = CString::new(json_str).unwrap();
        let instance = create_instance(json.as_ptr() as *const u8);
        assert!(!instance.is_null(), "instance is null");
 
        let plaintext = b"hello world";
        let buf_size  = plaintext.len() + 16 + tag_len;
        let mut buffer = vec![0u8; buf_size];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
 
        let enc_len = encrypt(instance, buffer.as_mut_ptr(), plaintext.len() as u32);
        assert!(enc_len > 0, "encrypt returned 0");
 
        let dec_len = decrypt(instance, buffer.as_mut_ptr(), enc_len);
        assert_eq!(dec_len as usize, plaintext.len(), "decrypted size mismatch");
        assert_eq!(&buffer[..dec_len as usize], plaintext, "plaintext mismatch");
 
        destroy_instance(instance);
    }
 
    fn tamper_and_expect_zero(json_str: &str, tag_len: usize) {
        let json     = CString::new(json_str).unwrap();
        let instance = create_instance(json.as_ptr() as *const u8);
        assert!(!instance.is_null());
 
        let plaintext = b"hello world";
        let buf_size  = plaintext.len() + 16 + tag_len;
        let mut buffer = vec![0u8; buf_size];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
 
        let enc_len = encrypt(instance, buffer.as_mut_ptr(), plaintext.len() as u32);
        assert!(enc_len > 0);
 
        buffer[0] ^= 0xff; // tamper ciphertext
 
        let dec_len = decrypt(instance, buffer.as_mut_ptr(), enc_len);
        assert_eq!(dec_len, 0, "tampered data must fail MAC verification");
 
        destroy_instance(instance);
    }

    #[test]
    fn test_create_instance_valid_json() {
        let json = make_test_json();

        let instance = create_instance(json.as_ptr() as *const u8);

        assert!(
            !instance.is_null(),
            "create_instance returned null for a valid JSON"
        );

        unsafe {
            let inst = &*(instance as *const AESKey);

            assert_eq!(
                inst.key,
                [
                    0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb,
                    0xcc, 0xdd, 0xee, 0xff
                ],
                "AES key parsed wrong"
            );

            assert_eq!(
                inst.iv,
                [0u8; 16],
                "IV parsed wrong (must be zeroth)"
            );
        }

        destroy_instance(instance);
    }

    #[test]
    fn test_create_instance_invalid_json() {
        let json = CString::new(r#"{"key": "short", "iv": "bad"}"#).unwrap();

        let instance = create_instance(json.as_ptr() as *const u8);

        assert!(
            instance.is_null(),
            "create_instance must return null for an invalid JSON"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use std::ffi::CString;

        let json = CString::new(
            r#"{
                "key": "00112233445566778899aabbccddeeff",
                "iv":  "00000000000000000000000000000000"
            }"#,
        )
        .unwrap();

        let instance = create_instance(json.as_ptr() as *const u8);

        assert!(!instance.is_null(), "instance is null");

        let plaintext = b"hello world";
        let mut buffer = Vec::with_capacity(plaintext.len() + 16);

        buffer.extend_from_slice(plaintext);
        buffer.resize(plaintext.len() + 16, 0);

        // encrypt
        let enc_len = encrypt(
                instance,
                buffer.as_mut_ptr(),
                plaintext.len() as u32,
            );

        assert!(
            enc_len > plaintext.len() as u32,
            "encrypted size must be larger due to PKCS7 padding"
        );
        assert_eq!(enc_len % 16, 0, "ciphertext must be block-aligned");

        // decrypt
        let dec_len = decrypt(
                instance,
                buffer.as_mut_ptr(),
                enc_len,
            );

        assert_eq!(
            dec_len as usize,
            plaintext.len(),
            "decrypted size must match original plaintext size"
        );

        assert_eq!(
            &buffer[..dec_len as usize],
            plaintext,
            "decrypted plaintext mismatch"
        );

        destroy_instance(instance);
    }

    #[test]
    fn test_encrypt_with_null_instance() {
        let mut data = b"test".to_vec();

        let res = encrypt(
                std::ptr::null_mut(),
                data.as_mut_ptr(),
                data.len() as u32,
            );

        assert_eq!(res, 0);
    }

    #[test]
    fn test_get_type() {
        let t = get_type();
        assert_eq!(
            t,
            EncryptorType::EncryptorSymmetric as i32
        );
    }

        #[test]
    fn test_roundtrip_hmac_only() {
        roundtrip(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","hmac":"{HMAC_HEX}"}}"#),
            HMAC_TAG_LEN,
        );
    }
 
    #[test]
    fn test_roundtrip_cmac_only() {
        roundtrip(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","cmac":"{CMAC_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }
 
    #[test]
    fn test_roundtrip_both() {
        roundtrip(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","cmac":"{CMAC_HEX}","hmac":"{HMAC_HEX}"}}"#),
            BOTH_TAG_LEN,
        );
    }
 
    #[test]
    fn test_tamper_hmac_only() {
        tamper_and_expect_zero(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","hmac":"{HMAC_HEX}"}}"#),
            HMAC_TAG_LEN,
        );
    }
 
    #[test]
    fn test_tamper_cmac_only() {
        tamper_and_expect_zero(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","cmac":"{CMAC_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }
 
    #[test]
    fn test_tamper_both() {
        tamper_and_expect_zero(
            &format!(r#"{{"key":"{KEY_HEX}","iv":"{IV_HEX}","cmac":"{CMAC_HEX}","hmac":"{HMAC_HEX}"}}"#),
            BOTH_TAG_LEN,
        );
    }
}
