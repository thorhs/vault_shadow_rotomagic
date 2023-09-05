use clap::Parser;
use color_eyre::{eyre::bail, eyre::eyre, Result};

use std::io::Write;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

#[derive(clap::Parser, Debug)]
#[command(author, version, about)]
struct Options {
    /// Username to change password
    #[arg(long, env)]
    user: String,

    /// Password length
    #[arg(long, env, default_value_t = 32)]
    password_length: u8,

    /// Shadow file to change (for testing or otherwise)
    #[arg(long, env, default_value = "/etc/shadow")]
    shadow: PathBuf,

    /// Vault URL, if not set will use VAULT_ADDR
    #[arg(long, env)]
    vault_addr: Option<String>,

    /// Vault namespace
    #[arg(long, env)]
    vault_namespace: Option<String>,

    /// Vault token, if not set will use VAULT_TOKEN
    #[arg(long, env)]
    vault_token: Option<String>,

    /// Vault token file, if not set will use VAULT_TOKEN
    #[arg(long, env)]
    vault_token_path: Option<PathBuf>,

    /// Vault CA certificate, defaults to operating system CA store
    #[arg(long, env)]
    vault_ca_file: Option<PathBuf>,

    /// Vault don't verify CA certificate
    #[arg(long, env)]
    vault_insecure: bool,

    /// Vault kv2 mount path
    #[arg(long, env)]
    vault_mount: String,

    /// Vault kv2 secret path
    #[arg(long, env)]
    vault_path: Option<String>,
    /*
        /// Verify access to files before proceeding
        #[arg(long)]
        safe: bool,

        /// Lock file while editing
        #[arg(long)]
        lock: bool,
    */
}

impl Options {
    fn get_path(&self) -> String {
        if let Some(ref path) = self.vault_path {
            return path.to_string();
        }

        let hostname = gethostname::gethostname();

        let hostname = hostname.to_string_lossy();

        format!("{}/{}", hostname, self.user)
    }
}

async fn verify_shadow(options: &Options) -> Result<bool> {
    let file = std::fs::metadata(&options.shadow)?;

    if !file.is_file() {
        color_eyre::eyre::bail!("{:?} is not a file", options.shadow)
    }

    Ok(true)
}

/// Read contents of file, splitting each line into its fields
async fn read_file(options: &Options) -> Result<Vec<Vec<String>>> {
    let contents = tokio::fs::read_to_string(&options.shadow)
        .await
        .map_err(|e| eyre!(e).wrap_err("Reading shadow file"))?;

    let fields: Vec<Vec<String>> = contents
        .lines()
        .map(|line| line.split(':').map(ToString::to_string).collect())
        .collect();

    for (i, l) in fields.iter().enumerate() {
        if l.len() != 9 {
            bail!(
                "Number of fields on line {} is {}, was expecting 9",
                i + 1,
                l.len()
            );
        }
    }

    Ok(fields)
}

fn replace_password(
    mut input: Vec<Vec<String>>,
    username: &str,
    hash: &str,
) -> Result<Vec<Vec<String>>> {
    let mut first_line = None;

    for (i, l) in input.iter_mut().enumerate() {
        if let Some(u) = l.get(0) {
            if u == username {
                if first_line.is_some() {
                    bail!(
                        "Found duplicate username '{}' on line {}, first occurrance was at line {}",
                        username,
                        i,
                        first_line.unwrap()
                    );
                }
                l[1] = hash.to_string();
                first_line = Some(i);
            }
        }
    }

    if first_line.is_none() {
        bail!("User '{}' not found in shadow file", username);
    }

    Ok(input)
}

async fn write_output(options: &Options, output: Vec<Vec<String>>) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(false)
        .open(&options.shadow)
        .await?;

    let mut buf = Vec::<u8>::new();

    for line in output.iter() {
        buf.clear();
        writeln!(buf, "{}", line.join(":"))?;
        file.write_all(&buf).await?;
    }

    Ok(())
}

async fn create_vault_client(options: &Options) -> Result<VaultClient> {
    let mut vault_options = VaultClientSettingsBuilder::default();

    if let Some(ref url) = options.vault_addr {
        vault_options.address(url);
    }

    vault_options.namespace(options.vault_namespace.clone());
    vault_options.verify(!options.vault_insecure);

    if let Some(ref token) = options.vault_token {
        vault_options.token(token);
    }

    if let Some(ref token_path) = options.vault_token_path {
        let token = tokio::fs::read_to_string(token_path).await?;
        vault_options.token(token);
    }

    if let Some(ref ca_path) = options.vault_ca_file {
        vault_options.ca_certs(vec![ca_path.display().to_string()]);
    }

    let vault_options = vault_options.build()?;

    let vault_client = VaultClient::new(vault_options)?;

    Ok(vault_client)
}

async fn vault_store_password(
    options: &Options,
    vault_client: &VaultClient,
    password: &str,
    hash: &str,
) -> Result<()> {
    #[allow(unused_assignments)]
    let mut unix_timestamp = String::new();

    let mut data = std::collections::HashMap::<&str, &str>::new();
    data.insert("username", &options.user);
    data.insert("password", password);
    data.insert("password_hash", hash);

    if let Ok(timestamp) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        unix_timestamp = timestamp.as_secs().to_string();
        data.insert("changed_at", &unix_timestamp);
    }

    vaultrs::kv2::set(
        vault_client,
        &options.vault_mount,
        &options.get_path(),
        &data,
    )
    .await
    .map_err(|e| {
        let err_str = format!(
            "Error setting secret, mount: {}, path: {}.  {:?}",
            &options.vault_mount,
            &options.get_path(),
            &e,
        );
        eyre!(e).wrap_err(err_str)
    })?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().expect("Unable to install color_eyre hook");

    let options = Options::parse();

    println!("User: {}", options.user);
    println!("Shadow file: {:?}", options.shadow);

    // println!("Safe: {:?}", options.safe);
    // println!("Lock: {:?}", options.lock);

    println!(
        "File verification status: {}",
        verify_shadow(&options).await?
    );

    let input = read_file(&options).await?;

    let salt = generate_salt(&options)?;

    let password = generate_password(&options)?;

    let hash = pwhash::sha512_crypt::hash_with(salt.as_ref(), &password)?;

    let output = replace_password(input, &options.user, &hash)?;

    let vault_client = create_vault_client(&options).await?;

    vault_store_password(&options, &vault_client, &password, &hash).await?;

    write_output(&options, output).await?;

    Ok(())
}

fn generate_salt(_options: &Options) -> Result<String> {
    use rand::Rng;

    let mut salt_str = String::with_capacity(19);
    salt_str.push_str("$6$");
    const CHARSET: &str = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
    let mut rnd = rand::thread_rng();
    for _ in 0..16 {
        let pos = rnd.gen::<u8>() as usize & (CHARSET.len() - 1);
        salt_str.push(CHARSET.chars().nth(pos).unwrap());
    }

    Ok(salt_str.to_string())
}

fn generate_password(options: &Options) -> Result<String> {
    use rand::Rng;

    let mut password = String::with_capacity(options.password_length.into());
    const CHARSET: &str = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
    let mut rnd = rand::thread_rng();
    for _ in 0..options.password_length {
        let pos = rnd.gen::<u8>() as usize & (CHARSET.len() - 1);
        password.push(CHARSET.chars().nth(pos).unwrap());
    }

    Ok(password.to_string())
}
