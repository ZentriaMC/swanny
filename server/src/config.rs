use anyhow::{Context as _, Result, anyhow};
use clap::{ArgMatches, ValueEnum, arg, command, value_parser};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use swanny_ikev2::sa::ChildSaMode;
use toml::{Table, Value};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Mode {
    #[default]
    Transport,
    Tunnel,
}

impl From<Mode> for ChildSaMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Transport => ChildSaMode::Transport,
            Mode::Tunnel => ChildSaMode::Tunnel,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub address: IpAddr,
    pub peer_address: IpAddr,
    pub psk: Vec<u8>,
    pub expires: Option<u64>,
    pub mode: Mode,
    pub if_id: Option<u32>,
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
            .arg(
                arg!(
                    --expires <SECONDS> "SA expiry in seconds"
                )
                .required(false)
                .value_parser(value_parser!(u64)),
            )
            .arg(
                arg!(
                    --mode <MODE> "Child SA mode"
                )
                .required(false)
                .value_parser(value_parser!(Mode)),
            )
            .arg(
                arg!(
                    --"if-id" <ID> "XFRM interface ID"
                )
                .required(false)
                .value_parser(value_parser!(u32)),
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

        let expires: Option<u64> = config
            .get("expires")
            .map(|expires| {
                expires
                    .as_integer()
                    .ok_or_else(|| anyhow!("value must be integer"))
            })
            .transpose()?
            .map(|expires| expires.try_into())
            .transpose()?;

        let mode = match config
            .get("mode")
            .map(|mode| mode.as_str().ok_or_else(|| anyhow!("value must be string")))
            .transpose()?
        {
            Some("transport") | None => Mode::Transport,
            Some("tunnel") => Mode::Tunnel,
            Some(mode) => return Err(anyhow!("unknown Child SA mode: {}", mode)),
        };

        let if_id: Option<u32> = config
            .get("if_id")
            .map(|if_id| {
                if_id
                    .as_integer()
                    .ok_or_else(|| anyhow!("value must be integer"))
            })
            .transpose()?
            .map(|if_id| if_id.try_into())
            .transpose()?;

        Ok(Self {
            address,
            peer_address,
            psk,
            expires,
            mode,
            if_id,
        })
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let address = *matches.try_get_one::<IpAddr>("address")?.unwrap();
        let peer_address = *matches.try_get_one::<IpAddr>("peer-address")?.unwrap();
        let psk = matches.try_get_one::<String>("psk")?.unwrap().clone();
        let expires = matches.try_get_one::<u64>("expires")?.copied();
        let mode = matches
            .try_get_one::<Mode>("mode")?
            .unwrap_or(&Mode::default())
            .clone();
        let if_id = matches.try_get_one::<u32>("if-id")?.copied();
        Ok(Self {
            address,
            peer_address,
            psk: psk.as_bytes().to_vec(),
            expires,
            mode,
            if_id,
        })
    }
}

fn ip_addr_from_value(value: &Value) -> Result<IpAddr> {
    Ok(value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))?
        .parse()?)
}
