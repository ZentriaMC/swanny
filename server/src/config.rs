use anyhow::{Context as _, Result, anyhow};
use cidr::IpCidr;
use clap::{ArgMatches, ValueEnum, arg, command, value_parser};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use swanny_ikev2::message::payload::Id;
use swanny_ikev2::sa::ChildSaMode;
use toml::{Table, Value};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Mode {
    Transport,
    #[default]
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
    pub local_ts: Vec<IpCidr>,
    pub remote_ts: Vec<IpCidr>,
    pub psk: Vec<u8>,
    pub expires: Option<u64>,
    pub ike_lifetime: Option<u64>,
    pub dpd_interval: Option<u64>,
    pub mode: Mode,
    pub tunnel_id: String,
    pub grpc_listen: SocketAddr,
    pub initiate: bool,
    pub strict_ts: bool,
    pub local_identity: Option<Id>,
    pub remote_identity: Option<Id>,
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
                    --"local-ts" <CIDR> "Local traffic selector (CIDR, repeatable)"
                )
                .required(false)
                .action(clap::ArgAction::Append)
                .value_parser(|s: &str| s.parse::<IpCidr>().map_err(|err| err.to_string())),
            )
            .arg(
                arg!(
                    --"remote-ts" <CIDR> "Remote traffic selector (CIDR, repeatable)"
                )
                .required(false)
                .action(clap::ArgAction::Append)
                .value_parser(|s: &str| s.parse::<IpCidr>().map_err(|err| err.to_string())),
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
                    --"ike-lifetime" <SECONDS> "IKE SA lifetime in seconds (triggers rekey)"
                )
                .required(false)
                .value_parser(value_parser!(u64)),
            )
            .arg(
                arg!(
                    --"dpd-interval" <SECONDS> "Dead Peer Detection interval in seconds"
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
                    --"tunnel-id" <NAME> "Tunnel identifier"
                )
                .required(true),
            )
            .arg(
                arg!(
                    --"grpc-listen" <ADDRESS> "gRPC listen address"
                )
                .required(false)
                .default_value("[::1]:50051")
                .value_parser(value_parser!(SocketAddr)),
            )
            .arg(
                arg!(
                    --initiate "Auto-initiate IKE negotiation on startup"
                )
                .required(false)
                .action(clap::ArgAction::SetTrue),
            )
            .arg(
                arg!(
                    --"strict-ts" "Require exact traffic selector match"
                )
                .required(false)
                .action(clap::ArgAction::SetTrue),
            )
            .arg(
                arg!(
                    --"local-identity" <IDENTITY> "Local IKE identity (e.g. fqdn:vpn.example.com, email:user@example.com, keyid:device-01)"
                )
                .required(false)
                .value_parser(|s: &str| s.parse::<Id>().map_err(|err| err.to_string())),
            )
            .arg(
                arg!(
                    --"remote-identity" <IDENTITY> "Expected remote peer IKE identity for validation"
                )
                .required(false)
                .value_parser(|s: &str| s.parse::<Id>().map_err(|err| err.to_string())),
            )
            .get_matches();

        if let Some(file) = matches.get_one::<PathBuf>("config") {
            Self::from_file(file, &matches)
        } else {
            Self::from_matches(&matches)
        }
    }

    fn from_file(file: impl AsRef<Path>, matches: &ArgMatches) -> Result<Self> {
        let s = fs::read_to_string(file.as_ref())
            .with_context(|| format!("unable to read config file `{}`", file.as_ref().display()))?;
        let config = Table::from_str(&s).with_context(|| {
            format!("unable to parse config file `{}`", file.as_ref().display())
        })?;

        let tunnel_id = matches.try_get_one::<String>("tunnel-id")?.unwrap().clone();

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

        let ike_lifetime: Option<u64> = config
            .get("ike_lifetime")
            .map(|v| {
                v.as_integer()
                    .ok_or_else(|| anyhow!("value must be integer"))
            })
            .transpose()?
            .map(|v| v.try_into())
            .transpose()?;

        let dpd_interval: Option<u64> = config
            .get("dpd_interval")
            .map(|v| {
                v.as_integer()
                    .ok_or_else(|| anyhow!("value must be integer"))
            })
            .transpose()?
            .map(|v| v.try_into())
            .transpose()?;

        let mode = match config
            .get("mode")
            .map(|mode| mode.as_str().ok_or_else(|| anyhow!("value must be string")))
            .transpose()?
        {
            Some("transport") => Mode::Transport,
            Some("tunnel") | None => Mode::Tunnel,
            Some(mode) => return Err(anyhow!("unknown Child SA mode: {}", mode)),
        };

        let grpc_listen: SocketAddr = config
            .get("grpc_listen")
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or_else(|| anyhow!("grpc_listen must be a string"))?;
                s.parse::<SocketAddr>()
                    .map_err(|err| anyhow!("invalid grpc_listen: {err}"))
            })
            .transpose()?
            .unwrap_or_else(|| "[::1]:50051".parse().unwrap());

        let initiate = config
            .get("initiate")
            .map(|v| v.as_bool().ok_or_else(|| anyhow!("value must be boolean")))
            .transpose()?
            .unwrap_or(false);

        let strict_ts = config
            .get("strict_ts")
            .map(|v| v.as_bool().ok_or_else(|| anyhow!("value must be boolean")))
            .transpose()?
            .unwrap_or(false);

        let local_ts = parse_cidr_array(&config, "local_ts")?
            .unwrap_or_else(|| vec![IpCidr::new_host(address)]);
        let remote_ts = parse_cidr_array(&config, "remote_ts")?
            .unwrap_or_else(|| vec![IpCidr::new_host(peer_address)]);

        let local_identity: Option<Id> = config
            .get("local_identity")
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or_else(|| anyhow!("local_identity must be a string"))?;
                s.parse::<Id>()
                    .map_err(|err| anyhow!("invalid local_identity: {err}"))
            })
            .transpose()?;

        let remote_identity: Option<Id> = config
            .get("remote_identity")
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or_else(|| anyhow!("remote_identity must be a string"))?;
                s.parse::<Id>()
                    .map_err(|err| anyhow!("invalid remote_identity: {err}"))
            })
            .transpose()?;

        Ok(Self {
            address,
            peer_address,
            local_ts,
            remote_ts,
            psk,
            expires,
            ike_lifetime,
            dpd_interval,
            mode,
            tunnel_id,
            grpc_listen,
            initiate,
            strict_ts,
            local_identity,
            remote_identity,
        })
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let address = *matches.try_get_one::<IpAddr>("address")?.unwrap();
        let peer_address = *matches.try_get_one::<IpAddr>("peer-address")?.unwrap();
        let local_ts: Vec<IpCidr> = matches
            .get_many::<IpCidr>("local-ts")
            .map(|vals| vals.cloned().collect())
            .unwrap_or_else(|| vec![IpCidr::new_host(address)]);
        let remote_ts: Vec<IpCidr> = matches
            .get_many::<IpCidr>("remote-ts")
            .map(|vals| vals.cloned().collect())
            .unwrap_or_else(|| vec![IpCidr::new_host(peer_address)]);
        let psk = matches.try_get_one::<String>("psk")?.unwrap().clone();
        let expires = matches.try_get_one::<u64>("expires")?.copied();
        let ike_lifetime = matches.try_get_one::<u64>("ike-lifetime")?.copied();
        let dpd_interval = matches.try_get_one::<u64>("dpd-interval")?.copied();
        let mode = *matches
            .try_get_one::<Mode>("mode")?
            .unwrap_or(&Mode::default());
        let tunnel_id = matches.try_get_one::<String>("tunnel-id")?.unwrap().clone();
        let grpc_listen = *matches.try_get_one::<SocketAddr>("grpc-listen")?.unwrap();
        let initiate = matches.get_flag("initiate");
        let strict_ts = matches.get_flag("strict-ts");
        let local_identity = matches.try_get_one::<Id>("local-identity")?.cloned();
        let remote_identity = matches.try_get_one::<Id>("remote-identity")?.cloned();
        Ok(Self {
            address,
            peer_address,
            local_ts,
            remote_ts,
            psk: psk.as_bytes().to_vec(),
            expires,
            ike_lifetime,
            dpd_interval,
            mode,
            tunnel_id,
            grpc_listen,
            initiate,
            strict_ts,
            local_identity,
            remote_identity,
        })
    }
}

fn ip_addr_from_value(value: &Value) -> Result<IpAddr> {
    Ok(value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))?
        .parse()?)
}

fn parse_cidr_array(config: &Table, key: &str) -> Result<Option<Vec<IpCidr>>> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or_else(|| anyhow!("{key} must be an array"))?;
    let cidrs: Vec<IpCidr> = array
        .iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("{key} elements must be strings"))?;
            s.parse::<IpCidr>()
                .with_context(|| format!("invalid CIDR in {key}: {s}"))
        })
        .collect::<Result<_>>()?;
    Ok(Some(cidrs))
}
