use sha1::{Digest, Sha1};
use hex::encode;
use std::{ env, error::Error, fs::File, io::{BufRead, BufReader, Write}, };

const SHA1_HEX_STRING_LENGTH: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage:");
        eprintln!("SHA1-cracker: <wordlist.txt> <sha1_hash> <output.txt>");
        return Ok(());
    }

    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        return Err("Invalid SHA1 hash".into());
    }

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(wordlist_file);
    let output_path = &args[3];

    let mut output_file = File::create(output_path)?;

    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();

        let mut hasher = Sha1::new();
        hasher.update(common_password.as_bytes());
        let hash_result = hasher.finalize();
        let encoded_hash = encode(&hash_result);

        if hash_to_crack == &encoded_hash {
            println!("Password found: {}", common_password);
            writeln!(output_file, "Password: {}, SHA1 Hash: {}", common_password, encoded_hash)?;
            output_file.flush()?; // Flush the output file to ensure data is written immediately
            return Ok(());
        }
    }

    println!("Password not found in wordlist");
    Ok(())
} //done
