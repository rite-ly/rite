use clap::Args as ClapArgs;

use crate::system_info::gather_system;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Print build and environment details
    #[arg(long)]
    pub verbose: bool,
}

pub fn run(args: &Args) {
    let info = gather_system();
    println!("rite {}", info.build.version);
    if args.verbose {
        println!("target: {}", info.build.target);
        println!("profile: {}", info.build.profile);
        println!("features: {}", info.build.features);
        println!("commit: {}", info.build.commit);
        println!("commit_date: {}", info.build.commit_date);
        println!("build_date: {}", info.build.build_date);
        println!("rustc: {}", info.build.rustc);
        for backend in &info.backends {
            println!("{}: {}", backend.provider, backend.version);
            if let Some(source) = &backend.source {
                println!("{}_source: {source}", backend.provider);
            }
        }
        println!("os: {}", std::env::consts::OS);
        println!("arch: {}", std::env::consts::ARCH);
    }
}
