use std::error::Error;
use std::sync::Arc;
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;

#[derive(Parser)]
#[command(name = "root")]
#[command(about = "Nebula TorPortal Overlay Network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Directory used to persist this node's identity key and other local state.
    #[arg(long, global = true, default_value = "./data")]
    data_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Runs a decentralized relay node
    Node {
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        addr: String,

        #[arg(short, long, default_value = "localhost")]
        hostname: String,

        /// Address the Prometheus-style metrics HTTP endpoint listens on.
        #[arg(long, default_value = "0.0.0.0:9090")]
        metrics_addr: String,

        /// Path to an exit policy file (Tor-style `accept`/`reject <ip-or-cidr>:<port-or-*>`
        /// rules, evaluated in order, implicit final reject). See exit-policy.example.conf.
        /// If omitted, this relay rejects all exit (Begin) traffic and only forwards
        /// circuit-internal cells, i.e. it runs as a relay-only (non-exit) node.
        #[arg(long)]
        exit_policy: Option<String>,
    },
    /// Runs a client (OP) with SOCKS5 proxy
    Client {
        #[arg(short, long, default_value = "127.0.0.1:9050")]
        socks_addr: String,
    },
    /// Hosts a hidden service (.root site)
    Hs {
        #[arg(short, long, default_value = "127.0.0.1:80")]
        target: String,
    },
    /// Brute-forces an Ed25519 keypair whose .root address starts with the given prefix,
    /// then saves it to <data-dir>/identity.key for use with `node`/`hs`.
    Vanity {
        /// Desired prefix, base32 alphabet only (a-z, 2-7), case-insensitive.
        prefix: String,

        /// Number of worker threads. Defaults to all available CPU cores.
        #[arg(short, long)]
        threads: Option<usize>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    root::init_logging();
    let cli = Cli::parse();

    match cli.command {
        Commands::Node { addr, hostname, metrics_addr, exit_policy } => {
            log::info!("Starting Nebula Node on {}...", addr);
            let (cert_der, pk_der) = root::generate_self_signed_cert(&hostname)?;
            let server_config = root::create_server_config(cert_der.clone(), pk_der)?;
            let client_config = root::create_client_config()?;

            let exit_policy = match exit_policy {
                Some(path) => {
                    log::info!("Loading exit policy from {}", path);
                    root::ExitPolicy::load_from_file(&path)?
                }
                None => {
                    log::info!("No --exit-policy given; running relay-only (rejecting all exit traffic)");
                    root::ExitPolicy::reject_all()
                }
            };
            let exit_policy = Arc::new(exit_policy);

            let signing_key = root::load_or_create_signing_key(&cli.data_dir)?;
            let verifying_key = VerifyingKey::from(&signing_key);
            // tls_public_key carries this relay's TLS certificate DER so peers can pin
            // future connections to it once they've learned this (signed) descriptor.
            let descriptor = root::RelayDescriptor::new(verifying_key, addr.parse()?, cert_der.clone(), &signing_key)?;

            let directory = Arc::new(root::Directory::new());
            let peer_store = Arc::new(root::PeerStore::new());
            let circuit_manager = Arc::new(root::CircuitManager::new());
            let metrics = Arc::new(root::Metrics::new());

            let d_clone = directory.clone();
            let ps_clone = peer_store.clone();
            let c_config_clone = client_config.clone();
            tokio::spawn(async move {
                root::start_gossip_task(descriptor, ps_clone, d_clone, c_config_clone).await;
            });

            let m_clone = metrics.clone();
            let metrics_addr_clone = metrics_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = root::start_metrics_server(&metrics_addr_clone, m_clone).await {
                    log::error!("Metrics server exited with error: {}", e);
                }
            });

            let bw_manager = Arc::new(root::BandwidthManager::new(10 * 1024 * 1024));
            root::listen_for_connections(&addr, server_config, directory, circuit_manager, client_config, bw_manager, metrics, exit_policy).await?;
        }
        Commands::Client { socks_addr } => {
            log::info!("Starting Nebula Client (SOCKS5) on {}...", socks_addr);
            let directory = Arc::new(root::Directory::new());
            let circuit_manager = Arc::new(root::CircuitManager::new());
            let client_config = root::create_client_config()?;

            root::start_socks_proxy(&socks_addr, directory, circuit_manager, client_config).await?;
        }
        Commands::Vanity { prefix, threads } => {
            root::run_vanity_search(&prefix, threads, &cli.data_dir)?;
        }
        Commands::Hs { target } => {
            log::info!("Starting Hidden Service for target {}...", target);
            let directory = Arc::new(root::Directory::new());
            let client_config = root::create_client_config()?;
            let signing_key = root::load_or_create_signing_key(&cli.data_dir)?;

            root::start_hidden_service(&target, directory, client_config, signing_key).await?;
        }
    }

    Ok(())
}
