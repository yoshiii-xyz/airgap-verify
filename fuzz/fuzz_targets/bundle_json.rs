#![no_main]

use libfuzzer_sys::fuzz_target;
use sigstore_verify::types::Bundle;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 16 * 1024 * 1024 {
        if let Ok(json) = std::str::from_utf8(data) {
            let _ = Bundle::from_json(json);
        }
    }
});
