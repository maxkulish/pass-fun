use std::{error::Error, fmt::Debug, ops::{Range, RangeInclusive}, time::Instant, write};
use argh::FromArgs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::fmt;
use rayon::prelude::*;

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
    T: AsRef<str>
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
}

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
    }
}
