/// Root filesystem usage as an integer percentage, ported from the Go
/// implementation's syscall.Statfs("/") call.
#[allow(unsafe_code)]
pub fn root_used_percentage() -> std::io::Result<u64> {
    let path = std::ffi::CString::new("/")?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid NUL-terminated C string and `stat` is a
    // correctly sized, zeroed statfs the kernel fills in. Checked return value.
    let rc = unsafe { libc::statfs(path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let bsize = stat.f_bsize as u64;
    let total = stat.f_blocks as u64 * bsize;
    let free = stat.f_bfree as u64 * bsize;
    if total == 0 {
        return Ok(0);
    }
    let used = total.saturating_sub(free);
    // Go truncates via int(); match that rather than rounding.
    Ok((used as f64 / total as f64 * 100.0) as u64)
}
