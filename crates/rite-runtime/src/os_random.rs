//! Random bytes from the operating system.

use std::io;

use rand::TryRng;
use rand::rngs::SysRng;

/// `N` bytes from the operating system's random generator.
///
/// # Errors
///
/// Returns the generator's error if the operating system cannot supply bytes.
pub(crate) fn os_random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(io::Error::other)?;
    Ok(bytes)
}
