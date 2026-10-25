//! How much memory this machine (or the container or service slice the app
//! runs in) has, for sizing password hashing.
//!
//! On Linux this reads `/proc/meminfo` and narrows it by the tightest cgroup
//! (v1 or v2) memory limit on the process, so a container or a systemd
//! service with `MemoryMax=` is not mistaken for the whole machine. On other
//! systems it asks the operating system through the `sysinfo` crate (with the
//! `detect-memory` feature). doorward itself contains no `unsafe` code.

/// Memory figures in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    /// Physical memory the app may use at most.
    pub total: u64,
    /// Memory free for use right now.
    pub available: u64,
}

impl Memory {
    /// Figures supplied by the app, for example from its own configuration.
    /// `available` is clamped to `total`.
    pub fn new(total: u64, available: u64) -> Memory {
        Memory { total, available: available.min(total) }
    }
}

/// This machine's memory, narrowed by any cgroup limit (Linux), or `None`
/// when it can't be read. A `None` makes [`HashPolicy::tune`] fall back to
/// OWASP's minimum settings.
///
/// [`HashPolicy::tune`]: super::HashPolicy::tune
pub fn detect_memory() -> Option<Memory> {
    imp::detect()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::Memory;
    use std::path::{Path, PathBuf};

    pub fn detect() -> Option<Memory> {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut m = parse_meminfo(&info)?;
        let own = std::fs::read_to_string("/proc/self/cgroup").ok();
        if let Some((limit, used)) = own.as_deref().and_then(|own| cgroup_limit(own, Path::new("/sys/fs/cgroup"))) {
            m.total = m.total.min(limit);
            m.available = m.available.min(limit.saturating_sub(used));
        }
        Some(m)
    }

    pub(super) fn parse_meminfo(s: &str) -> Option<Memory> {
        let field = |name: &str| -> Option<u64> {
            s.lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        };
        let total = field("MemTotal")?;
        if total == 0 {
            return None;
        }
        // Kernels before 3.14 lack MemAvailable; free + cache is close enough.
        let available = field("MemAvailable")
            .or_else(|| Some(field("MemFree")?.saturating_add(field("Cached").unwrap_or(0))))
            .unwrap_or(total / 2);
        Some(Memory { total, available: available.min(total) })
    }

    /// The tightest memory limit on this process's cgroup or any parent, and
    /// what that cgroup uses now. `own` is the content of `/proc/self/cgroup`.
    pub(super) fn cgroup_limit(own: &str, root: &Path) -> Option<(u64, u64)> {
        // cgroup v2: one line "0::/path".
        if let Some(rel) = own.lines().find_map(|l| l.strip_prefix("0::")) {
            let rel = rel.trim().trim_start_matches('/');
            // Never follow ".." out of the cgroup tree.
            if rel.split('/').any(|part| part == "..") {
                return None;
            }
            let mut dir: PathBuf = root.join(rel);
            let mut best: Option<(u64, u64)> = None;
            while dir.starts_with(root) {
                if let Some(limit) = read_u64(&dir.join("memory.max")) {
                    let used = read_u64(&dir.join("memory.current")).unwrap_or(0);
                    if best.is_none_or(|(b, _)| limit < b) {
                        best = Some((limit, used));
                    }
                }
                if dir == root || !dir.pop() {
                    break;
                }
            }
            return best;
        }
        // cgroup v1.
        let dir = root.join("memory");
        let limit = read_u64(&dir.join("memory.limit_in_bytes"))?;
        // "No limit" is reported as a huge number.
        if limit >= 1 << 60 {
            return None;
        }
        Some((limit, read_u64(&dir.join("memory.usage_in_bytes")).unwrap_or(0)))
    }

    /// A number from a cgroup file; "max" (no limit) reads as nothing.
    fn read_u64(p: &Path) -> Option<u64> {
        std::fs::read_to_string(p).ok()?.trim().parse().ok()
    }
}

#[cfg(all(not(target_os = "linux"), feature = "detect-memory"))]
mod imp {
    use super::Memory;
    use sysinfo::{MemoryRefreshKind, RefreshKind, System};

    pub fn detect() -> Option<Memory> {
        let sys =
            System::new_with_specifics(RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()));
        let total = sys.total_memory();
        if total == 0 {
            return None;
        }
        Some(Memory { total, available: sys.available_memory().min(total) })
    }
}

#[cfg(all(not(target_os = "linux"), not(feature = "detect-memory")))]
mod imp {
    use super::Memory;

    pub fn detect() -> Option<Memory> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", feature = "detect-memory"))]
    #[test]
    fn this_machine_has_memory() {
        let m = super::detect_memory().expect("memory readable");
        assert!(m.total > 64 << 20 && m.available <= m.total, "{m:?}");
    }

    #[test]
    fn app_supplied_figures_are_clamped() {
        let m = super::Memory::new(100, 500);
        assert_eq!(m.available, 100);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn meminfo_parses() {
        let m =
            super::imp::parse_meminfo("MemTotal:        8000000 kB\nMemFree:  1000 kB\nMemAvailable:    6000000 kB\n")
                .unwrap();
        assert_eq!(m.total, 8_000_000 * 1024);
        assert_eq!(m.available, 6_000_000 * 1024);
        // Old kernels: free + cached.
        let m = super::imp::parse_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nCached: 300 kB\n").unwrap();
        assert_eq!(m.available, 400 * 1024);
        // Nonsense never panics or overflows.
        assert_eq!(super::imp::parse_meminfo("MemTotal: 0 kB\n"), None);
        assert_eq!(super::imp::parse_meminfo("MemTotal: 99999999999999999999 kB\n"), None);
        assert_eq!(super::imp::parse_meminfo(""), None);
        let m =
            super::imp::parse_meminfo("MemTotal: 18014398509481983 kB\nMemAvailable: 18014398509481983 kB\n").unwrap();
        assert_eq!(m.available, m.total);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_limits_are_found_and_escapes_refused() {
        let dir = std::env::temp_dir().join(format!("doorward-cg-{}", std::process::id()));
        let svc = dir.join("system.slice/app.service");
        std::fs::create_dir_all(&svc).unwrap();
        std::fs::write(dir.join("system.slice/memory.max"), "4294967296\n").unwrap();
        std::fs::write(dir.join("system.slice/memory.current"), "1000\n").unwrap();
        std::fs::write(svc.join("memory.max"), "1073741824\n").unwrap();
        std::fs::write(svc.join("memory.current"), "1073741000\n").unwrap();
        // The tighter limit (the service's) wins.
        assert_eq!(
            super::imp::cgroup_limit("0::/system.slice/app.service\n", &dir),
            Some((1_073_741_824, 1_073_741_000))
        );
        // "max" means no limit at that level.
        std::fs::write(svc.join("memory.max"), "max\n").unwrap();
        assert_eq!(super::imp::cgroup_limit("0::/system.slice/app.service\n", &dir), Some((4_294_967_296, 1000)));
        // A path that climbs out of the tree is ignored.
        assert_eq!(super::imp::cgroup_limit("0::/../../etc\n", &dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
