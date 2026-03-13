/// Secure overwrite a buffer (possibly containing secret data) with zero-bytes.
/// The write operation will not be optimized out by the compiler.
///
/// This is the Rust equivalent of Bitcoin Core's `memory_cleanse()` from
/// `support/cleanse.h`. It uses `std::ptr::write_volatile` to prevent the
/// compiler from eliding the zeroing as a dead store.
pub fn memory_cleanse(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // write_volatile is guaranteed not to be optimized away.
        // SAFETY: byte is a valid, aligned, dereferenceable pointer to a u8
        // within the mutable slice.
        unsafe {
            std::ptr::write_volatile(byte as *mut u8, 0);
        }
    }
    // Compiler fence to further prevent reordering or elimination.
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_cleanse_zeros_buffer() {
        let mut buf = [0xFFu8; 64];
        // Verify buffer is non-zero before cleanse.
        assert!(buf.iter().all(|&b| b == 0xFF));

        memory_cleanse(&mut buf);

        // Every byte must be zero after cleanse.
        assert!(buf.iter().all(|&b| b == 0), "buffer was not fully zeroed");
    }

    #[test]
    fn test_memory_cleanse_empty_buffer() {
        let mut buf = [0u8; 0];
        // Should not panic on empty input.
        memory_cleanse(&mut buf);
    }

    #[test]
    fn test_memory_cleanse_single_byte() {
        let mut buf = [0xABu8; 1];
        memory_cleanse(&mut buf);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_memory_cleanse_secret_key_sized() {
        // 32 bytes is a typical secret key size.
        let mut key = [0xDEu8; 32];
        memory_cleanse(&mut key);
        assert!(key.iter().all(|&b| b == 0));
    }
}
