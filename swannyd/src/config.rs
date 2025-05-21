use anyhow::{anyhow, Context as _, Result};
use clap::{arg, command, value_parser, ArgMatches};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::{Table, Value};

#[derive(Debug)]
pub struct Config {
    pub address: IpAddr,
    pub peer_address: IpAddr,
    pub psk: Vec<u8>,
}

impl Config {
    pub fn new() -> Result<Self> {
        let matches = command!()
            .arg(
                arg!(
                    -c --config <FILE> "Path to configuration file"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(
                    --address <ADDRESS> "Address"
                )
                .required(true)
                .value_parser(value_parser!(IpAddr)),
            )
            .arg(
                arg!(
                    --"peer-address" <ADDRESS> "Peer address"
                )
                .required(true)
                .value_parser(value_parser!(IpAddr)),
            )
            .arg(
                arg!(
                    --psk <PSK> "Pre shared key"
                )
                .required(true),
            )
            .get_matches();

        if let Some(file) = matches.get_one::<PathBuf>("config") {
            Self::from_file(file)
        } else {
            Self::from_matches(&matches)
        }
    }

    fn from_file(file: impl AsRef<Path>) -> Result<Self> {
        let s = fs::read_to_string(file.as_ref())
            .with_context(|| format!("unable to read config file `{}`", file.as_ref().display()))?;
        let config = Table::from_str(&s).with_context(|| {
            format!("unable to parse config file `{}`", file.as_ref().display())
        })?;

        let address = config
            .get("address")
            .with_context(|| "address not speficied".to_string())?;
        let address = ip_addr_from_value(address)?;

        let peer_address = config
            .get("peer_address")
            .with_context(|| "peer_address not speficied".to_string())?;
        let peer_address = ip_addr_from_value(peer_address)?;

        let psk = config
            .get("psk")
            .with_context(|| "psk not speficied".to_string())?
            .as_str()
            .ok_or_else(|| anyhow!("value must be string"))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            address,
            peer_address,
            psk,
        })
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let address = *matches.try_get_one::<IpAddr>("address")?.unwrap();
        let peer_address = *matches.try_get_one::<IpAddr>("peer-address")?.unwrap();
        let psk = matches.try_get_one::<String>("psk")?.unwrap().clone();
        Ok(Self {
            address,
            peer_address,
            psk: psk.as_bytes().to_vec(),
        })
    }
}

fn ip_addr_from_value(value: &Value) -> Result<IpAddr> {
    Ok(value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))?
        .parse()?)
}
