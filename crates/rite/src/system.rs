//! `rite system`: what the platform, network and security-feature probes
//! report on this machine, for checking them on a new system.

#[cfg(feature = "verification")]
pub fn run() {
    let build = crate::system_info::build_info();
    println!(
        "rite {} commit {} target {}",
        build.version, build.commit, build.target
    );
    print!("{}", rite_stdlib::probe_report());
}

#[cfg(not(feature = "verification"))]
pub fn run() {
    eprintln!("error: this build has no probes (the `verification` feature is off)");
    std::process::exit(1);
}
