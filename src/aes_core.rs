use tfhe::prelude::*;
use tfhe::FheUint8;
use crate::types::{State, ExpandedKey, NR};

// AES S-box lookup table
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// AES encryption function
pub fn encrypt_block(state: &mut State, expanded_key: &ExpandedKey, client_key: &ClientKey) {
    // Initial round
    add_round_key(state, &expanded_key.round_keys[0]);
    
    // Main rounds
    for round in 1..NR {
        sub_bytes(state, client_key);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_key.round_keys[round]);
    }
    
    // Final round (no mix columns)
    sub_bytes(state, client_key);
    shift_rows(state);
    add_round_key(state, &expanded_key.round_keys[NR]);
}

// Homomorphic S-box implementation
pub fn sub_byte(input: &FheUint8, client_key: &ClientKey) -> FheUint8 {
    let mut result = FheUint8::encrypt(0u8, client_key);
    
    // Create lookup table for homomorphic s-box
    for i in 0..256 {
        let condition = input._eq(&FheUint8::encrypt(i as u8, client_key));
        let s_box_value = FheUint8::encrypt(SBOX[i], client_key);
        result = result.add_with_condition(&s_box_value, &condition);
    }
    
    result
}

// SubBytes transformation
pub fn sub_bytes(state: &mut State, client_key: &ClientKey) {
    for i in 0..4 {
        for j in 0..4 {
            state.data[i][j] = sub_byte(&state.data[i][j], client_key);
        }
    }
}

// ShiftRows transformation
pub fn shift_rows(state: &mut State) {
    // No need to shift row 0
    
    // Shift row 1 by 1 position
    let temp = state.data[1][0].clone();
    for j in 0..3 {
        state.data[1][j] = state.data[1][j + 1].clone();
    }
    state.data[1][3] = temp;
    
    // Shift row 2 by 2 positions
    for j in 0..2 {
        let temp = state.data[2][j].clone();
        state.data[2][j] = state.data[2][j + 2].clone();
        state.data[2][j + 2] = temp;
    }
    
    // Shift row 3 by 3 positions (or 1 position left)
    let temp = state.data[3][3].clone();
    for j in (1..4).rev() {
        state.data[3][j] = state.data[3][j - 1].clone();
    }
    state.data[3][0] = temp;
}

// MixColumns transformation
pub fn mix_columns(state: &mut State) {
    for i in 0..4 {
        let column = [
            state.data[0][i].clone(),
            state.data[1][i].clone(),
            state.data[2][i].clone(),
            state.data[3][i].clone()
        ];
        
        let mut new_column = [
            FheUint8::trivial(0u8),
            FheUint8::trivial(0u8),
            FheUint8::trivial(0u8),
            FheUint8::trivial(0u8)
        ];

        // Matrix multiplication in GF(2^8)
        new_column[0] = &gmul(&column[0], 2) + &gmul(&column[1], 3) + &column[2] + &column[3];
        new_column[1] = &column[0] + &gmul(&column[1], 2) + &gmul(&column[2], 3) + &column[3];
        new_column[2] = &column[0] + &column[1] + &gmul(&column[2], 2) + &gmul(&column[3], 3);
        new_column[3] = &gmul(&column[0], 3) + &column[1] + &column[2] + &gmul(&column[3], 2);
        
        // Update state with new column
        for j in 0..4 {
            state.data[j][i] = new_column[j].clone();
        }
    }
}

// AddRoundKey transformation
pub fn add_round_key(state: &mut State, round_key: &[FheUint8]) {
    for i in 0..4 {
        for j in 0..4 {
            state.data[i][j] = &state.data[i][j] + &round_key[i * 4 + j];
        }
    }
}

// Galois field multiplication
pub fn gmul(a: &FheUint8, b: u8) -> FheUint8 {
    let mut p = a.clone();
    let mut result = FheUint8::trivial(0u8);
    
    // Implement Russian Peasant Multiplication in GF(2^8)
    for i in 0..8 {
        if (b >> i) & 1 == 1 {
            result = &result + &p;
        }
        
        let high_bit = (p.clone() >> 7) & FheUint8::one();
        p = (p << 1) ^ (high_bit * FheUint8::trivial(0x1b));
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::{ConfigBuilder, generate_keys};
    use crate::types::{State, ExpandedKey};

    fn setup() -> (ClientKey, ServerKey) {
        let config = ConfigBuilder::default()
            .noise_margin(2f64.powi(-64))
            .build();
        generate_keys(config)
    }

    #[test]
    fn test_sub_byte() {
        let (client_key, _) = setup();
        let input = FheUint8::encrypt(0x53, &client_key);
        let result = sub_byte(&input, &client_key);
        assert_eq!(result.decrypt(&client_key), 0xed);
    }

    #[test]
    fn test_shift_rows() {
        let (client_key, _) = setup();
        let mut state = State::new(&client_key);
        
        // Initialize test state
        for i in 0..4 {
            for j in 0..4 {
                state.data[i][j] = FheUint8::encrypt((i * 4 + j) as u8, &client_key);
            }
        }
        
        shift_rows(&mut state);
        
        // Verify first row unchanged
        assert_eq!(state.data[0][0].decrypt(&client_key), 0);
        assert_eq!(state.data[0][1].decrypt(&client_key), 1);
        assert_eq!(state.data[0][2].decrypt(&client_key), 2);
        assert_eq!(state.data[0][3].decrypt(&client_key), 3);
        
        // Verify other rows shifted
        assert_eq!(state.data[1][0].decrypt(&client_key), 5);
        assert_eq!(state.data[2][0].decrypt(&client_key), 10);
        assert_eq!(state.data[3][0].decrypt(&client_key), 15);
    }

    #[test]
    fn test_gmul() {
        let (client_key, _) = setup();
        
        // Test multiplication by 2
        let a = FheUint8::encrypt(0x57, &client_key);
        let result = gmul(&a, 2);
        assert_eq!(result.decrypt(&client_key), 0xae);
        
        // Test multiplication by 3
        let result = gmul(&a, 3);
        assert_eq!(result.decrypt(&client_key), 0xf9);
    }
}