use clap::Parser;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder};

use fhe_aes::{State, ExpandedKey, encrypt_block};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    number_of_outputs: usize,
    
    #[arg(long)]
    iv: String,
    
    #[arg(long)]
    key: String,
}

fn main() {
    let args = Args::parse();
    
    // Parse inputs
    let key = hex::decode(&args.key).expect("Invalid key");
    let iv = hex::decode(&args.iv).expect("Invalid IV");
    
    // Generate keys
    let config = ConfigBuilder::default()
        .noise_margin(2f64.powi(-64))
        .build();
    let (client_key, server_key) = generate_keys(config);
    
    // Key expansion
    let start = Instant::now();
    let expanded_key = ExpandedKey::new(&key, &client_key);
    let key_expansion_elapsed = start.elapsed();
    println!("AES key expansion took: {:?}", key_expansion_elapsed);
    
    // Encryption
    let start = Instant::now();
    for i in 0..args.number_of_outputs {
        let mut state = State::from_bytes(&iv, &client_key);
        encrypt_block(&mut state, &expanded_key,&client_key);
    }
    let elapsed = start.elapsed();
    println!("AES of #{} outputs computed in: {:?}", args.number_of_outputs, elapsed);
}