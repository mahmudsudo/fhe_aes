# Homomorphic AES-128 Implementation using TFHE-rs

This project implements a homomorphic version of the AES-128 cryptosystem using the TFHE-rs library. The implementation focuses on performance optimization while maintaining security requirements.

## Features

- Complete FHE AES-128 implementation
- Separated key expansion and encryption phases
- Performance-optimized homomorphic operations
- Security requirements:
  - Failure probability < 2^-64
  - Security level ≥ 2^128
- AVX512 support for enhanced performance
- Comprehensive test suite with standard vectors

## Prerequisites

- Rust (nightly toolchain required)
- Cargo
- AVX512 support (for optimal performance)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/fhe-aes.git
cd fhe-aes
```

2. Build the project:
```bash
cargo build --release --features nightly-avx512
```

## Usage

### Command Line Interface

The executable accepts the following parameters:
- `--number-of-outputs`: Number of AES outputs to generate
- `--iv`: Initialization vector (16 bytes in hex)
- `--key`: AES key (16 bytes in hex)

Example usage:
```bash
cargo run --release -- \
  --number-of-outputs 1 \
  --iv 000102030405060708090a0b0c0d0e0f \
  --key 2b7e151628aed2a6abf7158809cf4f3c
```

### Library Usage

```rust
use fhe_aes::{State, ExpandedKey, encrypt_block};
use tfhe::{ConfigBuilder, generate_keys};

// Generate keys
let config = ConfigBuilder::default()
    .noise_margin(2f64.powi(-64))
    .build();
let (client_key, server_key) = generate_keys(config);

// Initialize state and key
let key = [0u8; 16];  // Replace with your key
let mut state = State::from_bytes(&[0u8; 16], &client_key);
let expanded_key = ExpandedKey::new(&key, &client_key);

// Encrypt
encrypt_block(&mut state, &expanded_key, &client_key);

// Get result
let result = state.to_bytes(&client_key);
```

## Implementation Details

### Project Structure

- `src/lib.rs`: Main library exports and module definitions
- `src/types.rs`: Core data structures (State, ExpandedKey)
- `src/aes_core.rs`: AES operations implementation

### Key Components

1. **State Management**
   - `State` struct for managing AES state matrix
   - Efficient conversion between bytes and encrypted format

2. **Key Expansion**
   - Separated offline phase
   - Round key generation with S-box operations

3. **Core Operations**
   - SubBytes transformation using homomorphic lookup
   - ShiftRows for byte permutation
   - MixColumns using Galois Field arithmetic
   - AddRoundKey for key mixing

### Performance Optimizations

1. **Memory Management**
   - Pre-allocated vectors
   - Minimized cloning operations
   - Efficient state transformations

2. **Computation Optimizations**
   - AVX512 acceleration
   - Optimized Galois Field operations
   - Efficient homomorphic S-box implementation

## Testing

Run the test suite:
```bash
cargo test
```

Run benchmarks:
```bash
cargo bench
```

## Benchmarking

All benchmarks are conducted on an AWS hpc7a.96xlarge instance with:
- AVX512 enabled
- Nightly toolchain
- Release build

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on the ISO/IEC 18033-4 standard
- Optimizations inspired by recent research in FHE
- TFHE-rs library and community

## Security Notes

- Implements required security parameters
  - Failure probability < 2^-64
  - Security level ≥ 2^128
- Uses TFHE-rs's secure parameter sets
- Regular security audits recommended

## Performance Considerations

For optimal performance:
1. Use release builds
2. Enable AVX512 feature
3. Run on compatible hardware
4. Consider key expansion as an offline phase
5. Batch operations when possible

## References

1. ISO/IEC 18033-4 standard
2. TFHE-rs documentation
3. Advanced Encryption Standard (AES) specification
