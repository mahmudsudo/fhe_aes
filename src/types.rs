use tfhe::prelude::*;
use tfhe::FheUint8;

// Constants for AES-128
pub const NB: usize = 4;  // Number of columns in state
pub const NK: usize = 4;  // Number of 32-bit words in key
pub const NR: usize = 10; // Number of rounds

// Round constants
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// AES state matrix
#[derive(Clone)]
pub struct State {
    pub data: Vec<Vec<FheUint8>>,
}

impl State {
    pub fn new(client_key: &ClientKey) -> Self {
        let data = vec![vec![FheUint8::encrypt(0u8, client_key); 4]; 4];
        State { data }
    }
    
    pub fn from_bytes(bytes: &[u8], client_key: &ClientKey) -> Self {
        let mut data = vec![vec![FheUint8::encrypt(0u8, client_key); 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                data[j][i] = FheUint8::encrypt(bytes[i * 4 + j], client_key);
            }
        }
        State { data }
    }

    pub fn to_bytes(&self, client_key: &ClientKey) -> Vec<u8> {
        let mut result = vec![0u8; 16];
        for i in 0..4 {
            for j in 0..4 {
                result[i * 4 + j] = self.data[j][i].decrypt(client_key);
            }
        }
        result
    }
}

// Key expansion
pub struct ExpandedKey {
    pub round_keys: Vec<Vec<FheUint8>>,
}

impl ExpandedKey {
    pub fn new(key: &[u8], client_key: &ClientKey) -> Self {
        let mut w = Vec::with_capacity(NB * (NR + 1));
        
        // First NK words are the original key
        for i in 0..NK {
            let mut word = Vec::with_capacity(4);
            for j in 0..4 {
                word.push(FheUint8::encrypt(key[4*i + j], client_key));
            }
            w.push(word);
        }
        
        // Generate remaining words
        for i in NK..(NB * (NR + 1)) {
            let mut temp = w[i-1].clone();
            
            if i % NK == 0 {
                // Rotate word
                let t = temp.remove(0);
                temp.push(t);
                
                // Apply S-box
                for j in 0..4 {
                    temp[j] = crate::aes_core::sub_byte(&temp[j], client_key);
                }
                
                // XOR with round constant
                let rcon = FheUint8::encrypt(RCON[i/NK - 1], client_key);
                temp[0] = &temp[0] + &rcon;
            }
            
            // XOR with word NK positions earlier
            let mut new_word = Vec::with_capacity(4);
            for j in 0..4 {
                new_word.push(&w[i-NK][j] + &temp[j]);
            }
            w.push(new_word);
        }
        
        // Convert to round keys format
        let mut round_keys = Vec::with_capacity(NR + 1);
        for i in 0..=NR {
            let mut round_key = Vec::with_capacity(16);
            for j in 0..4 {
                for k in 0..4 {
                    round_key.push(w[i*4 + k][j].clone());
                }
            }
            round_keys.push(round_key);
        }
        
        ExpandedKey { round_keys }
    }
}