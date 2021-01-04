use std::error::Error;
use argh::FromArgs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::fs::File;

/// Maps username to passwords
#[derive(Clone, Default, Serialize, Deserialize)]
struct Database {
    records: HashMap<String, Vec<u8>>,
}

impl Database {
    const PATH: &'static str = "users.db";

    fn load_or_create() -> Result<Self, Box<dyn Error>> {
        Ok(match File::open(Self::PATH) {
            Ok(f) => bincode::deserialize_from(f)?,
            Err(_) => Default::default(),
        })
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let f = File::create(Self::PATH)?;
        Ok(bincode::serialize_into(f, self)?)
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
}

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
    }
}
