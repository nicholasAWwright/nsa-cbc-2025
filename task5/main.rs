use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::time::Instant;

const KNOWN_PADDING: [u8; 16] = [0x10; 16];
const MAX_KEY_VALUE: u64 = 1 << 26; // 67,108,864

#[derive(Parser)]
#[command(name = "aes-attack")]
#[command(about = "Double AES-128-ECB Cryptanalysis Tool", long_about = None)]
struct Args {
    /// Attack mode
    #[arg(value_enum, required = true)]
    mode: Mode,

    /// Use reduced keyspace (2^16) for demonstration
    #[arg(long)]
    demo: bool,

    /// Plaintext (hex) - required for mitm mode
    #[arg(long)]
    plaintext: Option<String>,

    /// Ciphertext (hex) - required for mitm and final verification
    #[arg(long)]
    ciphertext: Option<String>,

    /// Padding ciphertext encrypted with K2 only (hex) - required for padding mode
    #[arg(long)]
    padding_k2: Option<String>,

    /// Padding ciphertext encrypted with both K1 and K2 (hex) - required for padding mode
    #[arg(long)]
    padding_k1k2: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    /// Meet-in-the-middle attack
    Mitm,
    /// Sequential padding attack
    Padding,
}

/// Construct 16-byte AES key from integer value
fn construct_key(key_value: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = key_value.to_le_bytes();
    key[..8].copy_from_slice(&bytes);
    key
}

/// Encrypt data with AES-128-ECB
fn aes_encrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut block = aes::Block::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Decrypt data with AES-128-ECB
fn aes_decrypt(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut block = aes::Block::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    block.into()
}

/// Format duration into human-readable time
fn format_time(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        format!("{:.1}m", secs / 60.0)
    } else {
        format!("{:.1}h", secs / 3600.0)
    }
}

/// Meet-in-the-middle attack
fn meet_in_the_middle_attack(
    plaintext: &[u8; 16],
    ciphertext: &[u8; 16],
    max_key: u64,
) -> Option<(u64, u64)> {
    println!("{}", "=".repeat(70));
    println!("Meet-in-the-Middle Attack");
    println!("{}", "=".repeat(70));
    println!(
        "\n[*] Keyspace per key: 2^{} = {} values",
        (max_key as f64).log2() as u32,
        max_key
    );
    println!("[*] Total key combinations: {}", max_key * max_key);
    println!("\n[*] Plaintext:  {}", hex::encode(plaintext));
    println!("[*] Ciphertext: {}\n", hex::encode(ciphertext));

    // Phase 1: Build forward encryption table
    println!("[Phase 1] Building forward table: E_K1(P) for all K1");
    println!("{}", "-".repeat(70));

    let mut forward_table = HashMap::new();
    let start = Instant::now();

    let pb = ProgressBar::new(max_key);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>10}/{len:10} ({percent}%) ETA: {eta}")
            .unwrap()
    );

    for k1 in 0..max_key {
        let key1 = construct_key(k1);
        let intermediate = aes_encrypt(&key1, plaintext);
        forward_table.insert(intermediate, k1);

        if k1 % 100000 == 0 {
            pb.set_position(k1);
        }
    }
    pb.finish_with_message("Phase 1 complete");

    let phase1_time = start.elapsed().as_secs_f64();
    println!(
        "\n[✓] Phase 1 complete: {} entries in {}",
        forward_table.len(),
        format_time(phase1_time)
    );

    // Phase 2: Backward decryption and collision detection
    println!("\n[Phase 2] Searching for collision: D_K2(C) in forward table");
    println!("{}", "-".repeat(70));

    let start = Instant::now();
    let pb = ProgressBar::new(max_key);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>10}/{len:10} ({percent}%) ETA: {eta}")
            .unwrap()
    );

    for k2 in 0..max_key {
        let key2 = construct_key(k2);
        let intermediate = aes_decrypt(&key2, ciphertext);

        if let Some(&k1) = forward_table.get(&intermediate) {
            pb.finish_with_message("Collision found!");
            let phase2_time = start.elapsed().as_secs_f64();
            let total_time = phase1_time + phase2_time;

            let key1 = construct_key(k1);
            let key2 = construct_key(k2);

            println!("\n{}", "=".repeat(70));
            println!("🎯 COLLISION FOUND!");
            println!("{}", "=".repeat(70));
            println!("\n[+] Key 1 (k1={}): {}", k1, hex::encode(&key1));
            println!("[+] Key 2 (k2={}): {}", k2, hex::encode(&key2));

            // Verify
            println!("\n[*] Verifying solution...");
            let step1 = aes_encrypt(&key1, plaintext);
            let step2 = aes_encrypt(&key2, &step1);

            if step2 == *ciphertext {
                println!("    ✓ Verification PASSED: E_K2(E_K1(P)) = C");
            } else {
                println!("    ✗ Verification FAILED");
            }

            println!("\n[*] Total time: {}", format_time(total_time));
            println!("    Phase 1: {}", format_time(phase1_time));
            println!("    Phase 2: {}", format_time(phase2_time));

            return Some((k1, k2));
        }

        if k2 % 100000 == 0 {
            pb.set_position(k2);
        }
    }

    pb.finish_with_message("Search complete");
    println!("\n[-] No collision found in keyspace");
    None
}

/// Sequential padding attack
fn padding_attack(
    padding_block: &[u8; 16],
    padding_k2_ciphertext: &[u8; 16],
    padding_k1k2_ciphertext: &[u8; 16],
    max_key: u64,
) -> Option<(u64, u64)> {
    println!("{}", "=".repeat(70));
    println!("Sequential Padding Attack");
    println!("{}", "=".repeat(70));
    println!(
        "\n[*] Keyspace: 2^{} = {} values per key",
        (max_key as f64).log2() as u32,
        max_key
    );

    // Phase 1: Find K2 using padding block encrypted with K2 only
    println!("\n[Phase 1] Finding K2 using padding block encrypted with K2");
    println!("{}", "-".repeat(70));
    println!("[*] Padding block:       {}", hex::encode(padding_block));
    println!(
        "[*] E_K2(padding):       {}\n",
        hex::encode(padding_k2_ciphertext)
    );

    let start_phase1 = Instant::now();
    let pb = ProgressBar::new(max_key);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>10}/{len:10} ({percent}%) ETA: {eta}")
            .unwrap()
    );

    let mut k2_found = None;

    for k2 in 0..max_key {
        let key2 = construct_key(k2);
        if aes_encrypt(&key2, padding_block) == *padding_k2_ciphertext {
            pb.finish_with_message("K2 found!");
            let phase1_time = start_phase1.elapsed().as_secs_f64();
            k2_found = Some(k2);

            println!("\n[✓] K2 FOUND!");
            println!("    k2={}: {}", k2, hex::encode(&key2));
            println!("    Time: {}", format_time(phase1_time));
            println!("    Searched {} keys", k2 + 1);
            break;
        }

        if k2 % 100000 == 0 {
            pb.set_position(k2);
        }
    }

    let k2_found = match k2_found {
        Some(k2) => k2,
        None => {
            pb.finish_with_message("Search complete");
            println!("\n[-] K2 not found in keyspace");
            return None;
        }
    };

    let phase1_time = start_phase1.elapsed().as_secs_f64();

    // Phase 2: Find K1 using padding block encrypted with K1 and K2
    // We now know K2, so we can decrypt once to get E_K1(padding)
    let key2 = construct_key(k2_found);
    let intermediate = aes_decrypt(&key2, padding_k1k2_ciphertext);

    println!("\n[Phase 2] Finding K1 using E_K1(E_K2(padding))");
    println!("{}", "-".repeat(70));
    println!("[*] Padding block:       {}", hex::encode(padding_block));
    println!(
        "[*] E_K1(E_K2(padding)): {}",
        hex::encode(padding_k1k2_ciphertext)
    );
    println!(
        "[*] D_K2(above) = E_K1(padding): {}\n",
        hex::encode(&intermediate)
    );

    let start_phase2 = Instant::now();
    let pb = ProgressBar::new(max_key);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>10}/{len:10} ({percent}%) ETA: {eta}")
            .unwrap()
    );

    let mut k1_found = None;

    for k1 in 0..max_key {
        let key1 = construct_key(k1);
        if aes_encrypt(&key1, padding_block) == intermediate {
            pb.finish_with_message("K1 found!");
            let phase2_time = start_phase2.elapsed().as_secs_f64();
            k1_found = Some(k1);

            println!("\n[✓] K1 FOUND!");
            println!("    k1={}: {}", k1, hex::encode(&key1));
            println!("    Time: {}", format_time(phase2_time));
            println!("    Searched {} keys", k1 + 1);
            break;
        }

        if k1 % 100000 == 0 {
            pb.set_position(k1);
        }
    }

    let k1_found = match k1_found {
        Some(k1) => k1,
        None => {
            pb.finish_with_message("Search complete");
            println!("\n[-] K1 not found in keyspace");
            return None;
        }
    };

    let phase2_time = start_phase2.elapsed().as_secs_f64();
    let total_time = phase1_time + phase2_time;

    println!("\n{}", "=".repeat(70));
    println!("🎯 BOTH KEYS FOUND!");
    println!("{}", "=".repeat(70));
    println!(
        "\n[+] K1 (k1={}): {}",
        k1_found,
        hex::encode(&construct_key(k1_found))
    );
    println!(
        "[+] K2 (k2={}): {}",
        k2_found,
        hex::encode(&construct_key(k2_found))
    );
    println!("\n[*] Total time: {}", format_time(total_time));
    println!("    Phase 1 (K2): {}", format_time(phase1_time));
    println!("    Phase 2 (K1): {}", format_time(phase2_time));

    Some((k1_found, k2_found))
}

fn main() {
    let args = Args::parse();

    let keyspace = if args.demo {
        println!("[!] DEMO MODE: Using reduced keyspace 2^16");
        println!("[!] Full attack requires 2^26 (~67M keys, takes minutes)\n");
        1 << 16
    } else {
        MAX_KEY_VALUE
    };

    println!("{}", "=".repeat(70));
    println!("Double AES-128-ECB Cryptanalysis Tool");
    println!("Targeting Weak Key Generation (26-bit entropy)");
    println!("{}", "=".repeat(70));
    println!("\nMode: {:?}", args.mode);
    println!("Keyspace: {} keys per key\n", keyspace);

    let result = match args.mode {
        Mode::Mitm => {
            // Parse required arguments for MITM mode
            let plaintext_str = args
                .plaintext
                .as_ref()
                .expect("--plaintext is required for mitm mode");
            let ciphertext_str = args
                .ciphertext
                .as_ref()
                .expect("--ciphertext is required for mitm mode");

            let plaintext = hex::decode_16(plaintext_str)
                .expect("Failed to decode plaintext (must be 32 hex characters)");
            let ciphertext = hex::decode_16(ciphertext_str)
                .expect("Failed to decode ciphertext (must be 32 hex characters)");

            meet_in_the_middle_attack(&plaintext, &ciphertext, keyspace)
        }
        Mode::Padding => {
            // Parse required arguments for padding mode
            let padding_k2_str = args
                .padding_k2
                .as_ref()
                .expect("--padding-k2 is required for padding mode");
            let padding_k1k2_str = args
                .padding_k1k2
                .as_ref()
                .expect("--padding-k1k2 is required for padding mode");

            let padding_k2_ciphertext = hex::decode_16(padding_k2_str)
                .expect("Failed to decode padding-k2 (must be 32 hex characters)");
            let padding_k1k2_ciphertext = hex::decode_16(padding_k1k2_str)
                .expect("Failed to decode padding-k1k2 (must be 32 hex characters)");

            // Use default padding block (PKCS#7 padding: 0x10 repeated)
            padding_attack(
                &KNOWN_PADDING,
                &padding_k2_ciphertext,
                &padding_k1k2_ciphertext,
                keyspace,
            )
        }
    };
}

// Helper module for hex encoding/decoding
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    pub fn decode_16(s: &str) -> Result<[u8; 16], String> {
        let vec = decode(s)?;
        if vec.len() != 16 {
            return Err(format!(
                "Expected 16 bytes (32 hex chars), got {} bytes",
                vec.len()
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}
