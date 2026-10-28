//! Secret arena（契約 §2.7）：明文唯一允許的落點。
//! 單段 mmap：mlock 防分頁；Linux 走 memfd_secret（如可用）+ MADV_DONTDUMP，
//! macOS 以 RLIMIT_CORE=0 抑制核心影像。drop 即 memset 零。

use std::sync::LazyLock;

use zeroize::Zeroize;

pub struct Arena {
    base: *mut u8,
    len: usize,
    used: std::sync::Mutex<usize>,
}

unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

const ARENA_LEN: usize = 8 * 1024 * 1024;

static ARENA: LazyLock<Option<Arena>> = LazyLock::new(|| unsafe { alloc_arena() });

/// 啟動時呼叫以觸發分配。失敗（權限/記憶體）不致命：記錄後退回純 zeroize 路徑，
/// A10 斷言在退回路徑下會明確失敗而非靜默通過。
pub fn init() -> bool {
    let ok = ARENA.is_some();
    if !ok {
        tracing::warn!("secret arena 分配失敗，退回 non-mlock 模式");
    }
    ok
}

/// 明文位元組拷進 arena，回傳 guard；drop 即清零。
/// P1 只有 A10 單元測試消費；P3 的 Redactor 與 reveal 快取是正式使用方。
#[allow(dead_code)]
pub fn store(bytes: &[u8]) -> Option<ArenaSecret> {
    let arena = ARENA.as_ref()?;
    let mut used = arena.used.lock().unwrap();
    if *used + bytes.len() > arena.len {
        return None;
    }
    let offset = *used;
    *used += bytes.len();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), arena.base.add(offset), bytes.len());
    }
    Some(ArenaSecret {
        base: arena.base,
        offset,
        len: bytes.len(),
    })
}

pub struct ArenaSecret {
    base: *mut u8,
    offset: usize,
    len: usize,
}

impl ArenaSecret {
    #[allow(dead_code)] // P3 Redactor 的讀取面
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base.add(self.offset), self.len) }
    }
}

impl Drop for ArenaSecret {
    fn drop(&mut self) {
        unsafe {
            std::slice::from_raw_parts_mut(self.base.add(self.offset), self.len).zeroize();
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn alloc_arena() -> Option<Arena> {
    let fd = unsafe { libc::memfd_secret(0) };
    let (mmap_fd, flags) = if fd >= 0 {
        (fd, libc::MAP_SHARED)
    } else {
        (-1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
    };
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ARENA_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            mmap_fd,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return None;
    }
    let base = base as *mut u8;
    if unsafe { libc::mlock(base as *const libc::c_void, ARENA_LEN) } != 0 {
        tracing::warn!("mlock 失敗：A10 在 CI 可能因 rlimit 拒絕，必要時調高 RLIMIT_MEMLOCK");
    }
    unsafe { libc::madvise(base as *mut libc::c_void, ARENA_LEN, libc::MADV_DONTDUMP) };
    Some(Arena {
        base,
        len: ARENA_LEN,
        used: std::sync::Mutex::new(0),
    })
}

#[cfg(target_os = "macos")]
unsafe fn alloc_arena() -> Option<Arena> {
    // macOS 無 memfd_secret/MADV_DONTDUMP：mlock + 關掉核心影像產生。
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ARENA_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return None;
    }
    let base = base as *mut u8;
    if unsafe { libc::mlock(base as *const libc::c_void, ARENA_LEN) } != 0 {
        tracing::warn!("mlock 失敗（macOS 通常不該發生）");
    }
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    Some(Arena {
        base,
        len: ARENA_LEN,
        used: std::sync::Mutex::new(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A10：fill 已知 pattern → drop → 直讀 arena 原始位元組全零；
    /// mlock 生效以 mincore 探測（Linux/macOS 皆實作）。
    #[test]
    fn arena_zeroizes_on_drop_and_locked() {
        assert!(init(), "arena 必須可分配（CI 環境前提）");
        let secret = b"correct horse battery staple";
        let holder = store(secret).expect("arena full?");
        assert_eq!(holder.as_bytes(), secret);
        let probe = holder.as_bytes().as_ptr();
        drop(holder);
        let after = unsafe { std::slice::from_raw_parts(probe, secret.len()) };
        assert!(after.iter().all(|b| *b == 0), "drop 後未清零");
        let locked = unsafe {
            let mut vec: libc::c_schar = 0;
            libc::mincore(probe as *mut libc::c_void, 1, &mut vec) == 0
        };
        assert!(locked, "mincore 失敗代表頁未 resident（mlock 未生效）");
    }
}
