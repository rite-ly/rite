use clap::Args as ClapArgs;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Print detailed build and environment diagnostics
    #[arg(long)]
    pub verbose: bool,
}

pub fn run(args: &Args) {
    println!("rite {}", env!("CARGO_PKG_VERSION"));
    if args.verbose {
        println!("target: {}", env!("RITE_BUILD_TARGET"));
        println!("profile: {}", env!("RITE_BUILD_PROFILE"));
        println!("features: {}", env!("RITE_BUILD_FEATURES"));
        println!("commit: {}", env!("RITE_BUILD_COMMIT"));
        println!("commit_date: {}", env!("RITE_BUILD_COMMIT_DATE"));
        println!("build_date: {}", env!("RITE_BUILD_DATE"));
        println!("rustc: {}", env!("RITE_BUILD_RUSTC"));
        #[cfg(feature = "openssl")]
        println!("openssl: {}", openssl::version::version());
        #[cfg(feature = "openssl")]
        println!("openssl_source: {}", openssl_source());
        println!("os: {}", std::env::consts::OS);
        println!("arch: {}", std::env::consts::ARCH);
    }
}

#[cfg(feature = "openssl")]
fn openssl_source() -> &'static str {
    if cfg!(feature = "openssl-vendored") {
        "vendored"
    } else {
        "system"
    }
}
