use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use memmap::MmapOptions;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::OpenOptions, io::SeekFrom};
use std::fmt;
use std::io::Seek;
use std::fs::File;
use std::{
    error::Error,
    fmt::Debug,
    ops::{Range, RangeInclusive},
    time::Instant,
    write,
};

const HASH_LENGTH: usize = 16;

/// Maps username to passwords
#[derive(Clone, Default, Serialize, Deserialize)]
struct Database {
    records: HashMap<String, Vec<u8>>,
}

impl Database {
    const PATH: &'static str = "users.db";

    fn load_or_create() -> Result<Self, Box<dyn Error>> {
        Ok(match File::open(Self::PATH) {
            // new: snap usage
            Ok(f) => bincode::deserialize_from(snap::read::FrameDecoder::new(f))?,
            Err(_) => Default::default(),
        })
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let f = File::create(Self::PATH)?;
        Ok(bincode::serialize_into(
            snap::write::FrameEncoder::new(f),
            self,
        )?)
    }

    /// Note: this function performs no locking whatsoever.
    /// Last closer wins.
    fn with<F, T>(f: F) -> Result<T, Box<dyn Error>>
    where
        F: FnOnce(&mut Self) -> Result<T, Box<dyn Error>>,
    {
        let mut db = Self::load_or_create()?;
        let res = f(&mut db);
        db.save()?;
        res
    }
}

struct Charset(Vec<u8>);

impl<T> From<T> for Charset
where
    T: AsRef<str>,
{
    fn from(t: T) -> Self {
        Self(t.as_ref().as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Charset {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Charset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.0 {
            let c = *c as char;
            if c.is_ascii_graphic() {
                write!(f, "{}", c)?;
            } else {
                write!(f, "\\x{:02x}", c as u64)?;
            }
        }
        Ok(())
    }
}

impl Charset {
    fn range(&self, output_len: u32) -> Range<u64> {
        0..(self.0.len() as u64).pow(output_len)
    }

    fn get_into(&self, i: u64, buf: &mut [u8]) {
        let n = self.0.len() as u64;

        let mut remain = i;
        for slot in buf.iter_mut() {
            let modulo = remain % n;
            *slot = self.0[modulo as usize];
            remain = (remain - modulo) / n;
        }
    }
}

/// Experiment with passwords.
#[derive(FromArgs)]
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    AddUser(AddUser),
    ListUsers(ListUsers),
    Auth(Auth),
    Bruteforce(Bruteforce),
    GenHtable(GenHtable),
    UseHtable(UseHtable),
}

#[derive(FromArgs)]
/// Use a hash table
#[argh(subcommand, name = "use-htable")]
struct UseHtable {}

#[derive(FromArgs)]
/// Generate a hash table
#[argh(subcommand, name = "gen-htable")]
struct GenHtable {}

#[derive(FromArgs)]
/// Try to brute-force user accounts
#[argh(subcommand, name = "bruteforce")]
struct Bruteforce {}

#[derive(FromArgs)]
/// Add a user to the database
#[argh(subcommand, name = "add-user")]
struct AddUser {
    #[argh(positional)]
    username: String,

    #[argh(positional)]
    password: String,
}

#[derive(FromArgs)]
/// List users
#[argh(subcommand, name = "list-users")]
struct ListUsers {}

#[derive(FromArgs)]
/// Authenticate as a user
#[argh(subcommand, name = "auth")]
struct Auth {
    #[argh(positional)]
    username: String,

    #[argh(positional)]
    password: String,
}
#[derive(Debug)]
struct BruteforceParams {
    len_range: RangeInclusive<usize>,
    charset: Charset,
}

fn bruteforce() -> Result<(), Box<dyn Error>> {
    let params = BruteforceParams {
        len_range: 4..=8,
        charset: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
    };
    println!("{:?}", params);

    let records = Database::with(|db| Ok(db.records.clone()))?;
    let start_time = Instant::now();

    for len in params.len_range.clone() {
        params
            .charset
            .range(len as _)
            .into_par_iter()
            .for_each_with(vec![0u8; len], |mut buf, i| {
                params.charset.get_into(i, &mut buf);
                let hash = md5::compute(&buf);

                for (db_user, db_hash) in &records {
                    if hash.as_ref() == db_hash {
                        println!(
                            "[CRACKED in {:?}] user ({}) has password ({})",
                            start_time.elapsed(),
                            db_user,
                            std::str::from_utf8(&buf).unwrap_or("<not utf-8>")
                        );
                    }
                }
            })
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct TableHeader {
    len: u32,
    charset: Vec<u8>,
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{bar:40.blue}] ({eta_precise} left)")
        .progress_chars("#>-")
}

fn gen_htable() -> Result<(), Box<dyn Error>> {
    let item_len = 6;
    let charset: Charset = "abcdefghijklmnopqrstuvwxyz0123456789".into();
    let total_hashes = charset.range(item_len).end;
    println!(
        "Generating {} hashes — for all items of length {}, with characters {:?}",
        total_hashes, item_len, charset
    );

    let progress = ProgressBar::new(total_hashes).with_style(progress_style());
    progress.enable_steady_tick(250);

    // Write the header and pre-size the file
    let hashes_offset_in_file = {
        let mut file = File::create("table.db")?;
        bincode::serialize_into(
            &mut file,
            &TableHeader {
                len: item_len,
                charset: charset.0.to_vec(),
            },
        )?;

        let hashes_offset_in_file = file.seek(SeekFrom::Current(0))?;
        let hashes_len = total_hashes * HASH_LENGTH as u64;

        let file_len = hashes_offset_in_file + hashes_len;
        file.set_len(file_len)?;

        hashes_offset_in_file
    };

    let max_bytes_per_chunk = {
        let gb: u64 = 1024 * 1024 * 1024;
        // Picked to keep memory usage low-enough and flush to disk often-enough
        2 * gb
    };
    let hashes_per_chunk = max_bytes_per_chunk / HASH_LENGTH as u64;
    let bytes_per_chunk = hashes_per_chunk * HASH_LENGTH as u64;
    let num_chunks = total_hashes / hashes_per_chunk;

    // For each chunk, one by one...
    for chunk_index in 0..num_chunks {
        // Show progress
        let hashes_done = chunk_index * hashes_per_chunk;
        progress.set_position(hashes_done);

        let file = OpenOptions::new().read(true).write(true).open("table.db")?;
        let chunk_offset_in_file = hashes_offset_in_file + chunk_index * bytes_per_chunk;
        let mut file = unsafe {
            MmapOptions::new()
                .offset(chunk_offset_in_file)
                .len(bytes_per_chunk as _)
                .map_mut(&file)
        }?;

        // Map `hashes_per_chunk` hashes into memory, so we can write to the file
        let hashes = unsafe {
            std::slice::from_raw_parts_mut(
                file.as_mut_ptr() as *mut [u8; HASH_LENGTH],
                hashes_per_chunk as _,
            )
        };

        // In the collection of "all outputs of this charset", this is
        // where our chunk starts.
        let first_item_index = chunk_index * hashes_per_chunk;

        // Enumerate gives us the position within the chunk.
        hashes.par_iter_mut().enumerate().for_each_with(
            vec![0u8; item_len as usize],
            |buf, (index_in_chunk, out)| {
                let item_index = first_item_index + index_in_chunk as u64;
                // Generate the candidate password
                charset.get_into(item_index, buf);
                // Hash it and store it to the file.
                *out = md5::compute(buf).0;
            },
        );
    }

    progress.finish();
    Ok(())
}

fn use_htable() -> Result<(), Box<dyn Error>> {
    let (header, hashes_offset_in_file) = {
        let mut file = File::open("table.db")?;
        let header: TableHeader = bincode::deserialize_from(&mut file)?;
        let offset = file.seek(SeekFrom::Current(0))?;
        (header, offset)
    };

    let charset = Charset(header.charset);
    let num_hashes = charset.range(header.len).end;

    let file = File::open("table.db")?;
    let file = unsafe { MmapOptions::new().offset(hashes_offset_in_file).map(&file) }?;
    let hashes = unsafe {
        std::slice::from_raw_parts(
            file.as_ptr() as *const [u8; HASH_LENGTH],
            num_hashes as usize,
        )
    };

    let records = Database::with(|f| Ok(f.records.clone()))?;
    let start_time = Instant::now();

    hashes.par_iter().enumerate().for_each_with(
        vec![0u8; header.len as usize],
        |buf, (item_index, hash)| {
            for (db_user, db_hash) in &records {
                if db_hash == hash {
                    charset.get_into(item_index as _, buf);
                    println!(
                        "[CRACKED in {:?}] user {} has password {}",
                        start_time.elapsed(),
                        db_user,
                        std::str::from_utf8(buf).unwrap_or("<not utf-8>")
                    );
                }
            }
        },
    );
    println!("Spent {:?} going through whole table", start_time.elapsed());

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    match args.command {
        Command::AddUser(args) => Database::with(|db| {
            db.records
                .insert(args.username.clone(), md5::compute(args.password).to_vec());

            println!("User {} added to database", args.username);
            Ok(())
        }),
        Command::ListUsers(_) => Database::with(|db| {
            println!("users:");
            for k in db.records.keys() {
                println!(" - {}", k);
            }
            Ok(())
        }),
        Command::Auth(args) => Database::with(|db| {
            let entered = md5::compute(args.password);
            match db.records.get(&args.username) {
                Some(stored) if stored == entered.as_ref() => {
                    println!("Authentication successful!");
                }
                Some(_) => {
                    println!("Bad password.");
                }
                None => {
                    println!("No such user")
                }
            }
            Ok(())
        }),
        Command::Bruteforce(_) => bruteforce(),
        Command::GenHtable(_) => gen_htable(),
        Command::UseHtable(_) => use_htable(),
    }
}
