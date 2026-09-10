#![allow(non_snake_case)]
use core::slice;
use std::{collections::HashMap, ffi::CString};

pub use silentpayments::bitcoin_hashes;
use bitcoin_hashes::hex::DisplayHex;
use silentpayments::receiving::Receiver;
pub use silentpayments::secp256k1;
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

use silentpayments::{receiving::Label, utils::receiving::calculate_shared_secret};

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[repr(C)]
pub struct OutputData {
    pubkey_bytes: *const u8,
    amount: u64,
}

#[repr(C)]
pub struct ReceiverData {
    b_scan_bytes: *const u8,
    B_spend_bytes: *const u8,
    is_testnet: bool,
    labels: *const u32,
    labels_len: u64,
}

#[repr(C)]
pub struct ParamData {
    outputs_data: *const *const OutputData,
    outputs_data_len: u64,
    tweak_bytes: *const u8,
    receiver_data: *const ReceiverData,
}

#[no_mangle]
pub extern "C" fn api_scan_outputs(data: *const ParamData) -> *mut i8 {
    let data = unsafe { &*data };

    let outputs_slice =
        unsafe { slice::from_raw_parts(data.outputs_data, data.outputs_data_len as usize) };

    let outputs_to_check: Vec<XOnlyPublicKey> = outputs_slice
        .iter()
        .filter_map(|&vout_data_ptr| {
            let vout_data = unsafe { &*vout_data_ptr };
            let pubkey_slice = unsafe { slice::from_raw_parts(vout_data.pubkey_bytes, 32) };
            XOnlyPublicKey::from_slice(pubkey_slice).ok()
        })
        .collect();

    let b_scan = unsafe {
        SecretKey::from_slice(slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().b_scan_bytes,
            32,
        ))
        .unwrap()
    };
    let B_spend = unsafe {
        PublicKey::from_slice(slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().B_spend_bytes,
            33,
        ))
        .unwrap()
    };
    let is_testnet = unsafe { data.receiver_data.as_ref().unwrap().is_testnet };
    let change_label = Label::new(b_scan, 0);

    let secp = secp256k1::Secp256k1::new();
    let mut sp_receiver = Receiver::new(
        0,
        b_scan.public_key(&secp),
        B_spend,
        change_label,
        is_testnet,
    )
    .unwrap();

    let labels = unsafe {
        slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().labels,
            data.receiver_data.as_ref().unwrap().labels_len as usize,
        )
    };
    for label_int in labels {
        let label = Label::new(b_scan, *label_int);
        sp_receiver.add_label(label).unwrap();
    }

    let tweak_data =
        unsafe { PublicKey::from_slice(slice::from_raw_parts(data.tweak_bytes, 33)).unwrap() };
    let shared_secret = calculate_shared_secret(tweak_data, b_scan).unwrap();
    let scanned_outputs_received = sp_receiver
        .scan_transaction(&shared_secret, outputs_to_check)
        .unwrap();

    let mut outputs: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (label, output) in scanned_outputs_received {
        let mut output_map = HashMap::new();
        for (x_only_pubkey, tweak) in output {
            output_map.insert(
                x_only_pubkey.to_string(),
                tweak.to_be_bytes().as_hex().to_string(),
            );
        }

        let result_label = if let Some(label) = label {
            label.as_string()
        } else {
            "None".to_string()
        };
        outputs.insert(result_label, output_map);
    }

    let serialized = serde_json::to_string(&outputs).unwrap();

    let c_str = CString::new(serialized).unwrap();
    let ptr = c_str.into_raw();

    ptr as *mut i8
}

// --- Persistent session API -------------------------------------------------
//
// `api_scan_outputs` above rebuilds a `Secp256k1` context, `Receiver`, and all
// `Label`s on every call. The session API below builds that state once and
// reuses it across many `api_session_scan` calls from the same caller — one
// session per calling isolate/thread, since `Receiver`/`Secp256k1` are not
// `Send`/`Sync`.
//
// Unlike `api_scan_outputs`, every function here treats its input as
// untrusted (server-influenced) bytes: malformed input returns a null/error
// sentinel instead of panicking, and the whole body is wrapped in
// `catch_unwind` as a hard backstop, since a panic unwinding across this
// `extern "C"` boundary would otherwise be undefined behavior / abort the
// host process. `api_scan_outputs`'s existing panic-on-bad-input behavior is
// deliberately left as-is — hardening it is a separate, general follow-up,
// not part of this session-scoped addition.

/// Persistent session: an interior-mutable `Receiver` (label state is only
/// mutated at creation) plus the scan key needed to recompute shared secrets.
pub struct SpSession {
    receiver: Receiver,
    b_scan: SecretKey,
}

/// Creates a session from a receiver config. Returns null on malformed input
/// or on internal panic — callers must null-check before use.
#[no_mangle]
pub extern "C" fn api_session_create(config: *const ReceiverData) -> *mut SpSession {
    if config.is_null() {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let config = unsafe { &*config };

        let b_scan = SecretKey::from_slice(unsafe {
            slice::from_raw_parts(config.b_scan_bytes, 32)
        })
        .ok()?;
        let B_spend = PublicKey::from_slice(unsafe {
            slice::from_raw_parts(config.B_spend_bytes, 33)
        })
        .ok()?;

        let secp = secp256k1::Secp256k1::new();
        let change_label = Label::new(b_scan, 0);
        let mut receiver = Receiver::new(
            0,
            b_scan.public_key(&secp),
            B_spend,
            change_label,
            config.is_testnet,
        )
        .ok()?;

        let labels = unsafe { slice::from_raw_parts(config.labels, config.labels_len as usize) };
        for label_int in labels {
            let label = Label::new(b_scan, *label_int);
            receiver.add_label(label).ok()?;
        }

        Some(Box::into_raw(Box::new(SpSession { receiver, b_scan })))
    }));

    match result {
        Ok(Some(ptr)) => ptr,
        _ => std::ptr::null_mut(),
    }
}

/// Destroys a session created by `api_session_create`. Safe to call with null.
#[no_mangle]
pub extern "C" fn api_session_destroy(session: *mut SpSession) {
    if session.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(session));
    }
}

/// Scans `outputs_data` against `tweak_bytes` using the given session.
/// Returns `"{}"` for the (overwhelmingly common) no-match case without a
/// serde round-trip, a JSON match map on a hit, or null on malformed input /
/// internal panic — callers must null-check before treating the result as a
/// string, and must still call `free_pointer` on any non-null result.
#[no_mangle]
pub extern "C" fn api_session_scan(
    session: *mut SpSession,
    outputs_data: *const *const OutputData,
    outputs_data_len: u64,
    tweak_bytes: *const u8,
) -> *mut i8 {
    if session.is_null() || outputs_data.is_null() || tweak_bytes.is_null() {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let session = unsafe { &mut *session };

        let outputs_slice =
            unsafe { slice::from_raw_parts(outputs_data, outputs_data_len as usize) };
        let outputs_to_check: Vec<XOnlyPublicKey> = outputs_slice
            .iter()
            .filter_map(|&vout_data_ptr| {
                if vout_data_ptr.is_null() {
                    return None;
                }
                let vout_data = unsafe { &*vout_data_ptr };
                let pubkey_slice = unsafe { slice::from_raw_parts(vout_data.pubkey_bytes, 32) };
                XOnlyPublicKey::from_slice(pubkey_slice).ok()
            })
            .collect();

        let tweak_data =
            PublicKey::from_slice(unsafe { slice::from_raw_parts(tweak_bytes, 33) }).ok()?;
        let shared_secret = calculate_shared_secret(tweak_data, session.b_scan).ok()?;

        let scanned = session
            .receiver
            .scan_transaction(&shared_secret, outputs_to_check)
            .ok()?;

        if scanned.is_empty() {
            return Some(ptr_from_str("{}"));
        }

        let mut outputs: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (label, output) in scanned {
            let mut output_map = HashMap::new();
            for (x_only_pubkey, tweak) in output {
                output_map.insert(
                    x_only_pubkey.to_string(),
                    tweak.to_be_bytes().as_hex().to_string(),
                );
            }
            let result_label = label.map(|l| l.as_string()).unwrap_or_else(|| "None".to_string());
            outputs.insert(result_label, output_map);
        }
        let serialized = serde_json::to_string(&outputs).ok()?;
        Some(ptr_from_str(&serialized))
    }));

    match result {
        Ok(Some(ptr)) => ptr,
        _ => std::ptr::null_mut(),
    }
}

fn ptr_from_str(s: &str) -> *mut i8 {
    CString::new(s).expect("no interior NUL in scan output").into_raw() as *mut i8
}

// --- v2 binary block decode+scan --------------------------------------------
//
// Decodes+scans exactly one `blockchain.tweaks.subscribe` v2 block record, as
// specified byte-for-byte in electrs-tweaks's `doc/tweaks_v2_protocol.md`
// (that doc is the authoritative source for this layout — treat any
// discrepancy here as a bug in this file, not in that spec). The caller
// base64-decodes the wire blob and hands this function the raw bytes; the
// server confirmed one block per push notification (never batched), so one
// call here corresponds to exactly one notification (ADR-0008's "batch per
// response chunk" is satisfied trivially — a chunk *is* one block).
//
// Layout: <u32 height LE><CompactSize tx_count>{<32B txid, internal/consensus
// order><33B tweak><CompactSize vout_count>{<CompactSize vout><32B
// xonly>}}. `txid` on the wire is NOT display order — it is reversed here
// before hex-encoding so every match record this function returns already
// carries the conventional display-hex txid (matching `blockchain.tweaks.get`
// and every other txid the wallet handles), keeping the byte-order gotcha
// fully contained in this decoder.

fn read_u32_le(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let bytes = buf.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Bitcoin-consensus CompactSize varint (`0xfd`/`0xfe`/`0xff` prefix forms).
fn read_compact_size(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    match first {
        0xfd => {
            let b = buf.get(*pos..*pos + 2)?;
            *pos += 2;
            Some(u16::from_le_bytes(b.try_into().ok()?) as u64)
        }
        0xfe => {
            let b = buf.get(*pos..*pos + 4)?;
            *pos += 4;
            Some(u32::from_le_bytes(b.try_into().ok()?) as u64)
        }
        0xff => {
            let b = buf.get(*pos..*pos + 8)?;
            *pos += 8;
            Some(u64::from_le_bytes(b.try_into().ok()?))
        }
        n => Some(n as u64),
    }
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let b = buf.get(*pos..*pos + n)?;
    *pos += n;
    Some(b)
}

/// Decodes+scans one v2 block record (`block_bytes`, already base64-decoded
/// by the caller) against `session`'s persistent receiver. Returns a JSON
/// array of match records `{height, txid, vout, label, output_pubkey,
/// tweak}` (txid in display-hex order, per the note above), `"[]"` for the
/// overwhelmingly common no-match case (no serde round-trip), or null on a
/// malformed block / internal panic — same untrusted-input contract as the
/// rest of the session API (ADR-0006).
#[no_mangle]
pub extern "C" fn api_session_scan_block_v2(
    session: *mut SpSession,
    block_bytes: *const u8,
    block_bytes_len: u64,
) -> *mut i8 {
    if session.is_null() || block_bytes.is_null() {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| -> Option<*mut i8> {
        let session = unsafe { &mut *session };
        let buf = unsafe { slice::from_raw_parts(block_bytes, block_bytes_len as usize) };
        let mut pos = 0usize;

        let height = read_u32_le(buf, &mut pos)?;
        let tx_count = read_compact_size(buf, &mut pos)?;

        let mut matches: Vec<serde_json::Value> = Vec::new();

        for _ in 0..tx_count {
            let txid_wire = read_bytes(buf, &mut pos, 32)?;
            // Wire order is internal/consensus order; every txid the wallet
            // otherwise handles (v1 JSON, `blockchain.tweaks.get`) is the
            // reversed display-hex string — reverse once, here, so nothing
            // downstream of this function needs to know the wire order exists.
            let mut txid_display = txid_wire.to_vec();
            txid_display.reverse();
            let txid_hex = txid_display.as_hex().to_string();

            let tweak_bytes = read_bytes(buf, &mut pos, 33)?;
            let tweak_data = PublicKey::from_slice(tweak_bytes).ok()?;
            let shared_secret = calculate_shared_secret(tweak_data, session.b_scan).ok()?;

            let vout_count = read_compact_size(buf, &mut pos)?;
            let mut vout_of: HashMap<XOnlyPublicKey, u64> = HashMap::new();
            let mut outputs_to_check: Vec<XOnlyPublicKey> = Vec::with_capacity(vout_count as usize);

            for _ in 0..vout_count {
                let vout = read_compact_size(buf, &mut pos)?;
                let xonly_bytes = read_bytes(buf, &mut pos, 32)?;
                // An unparseable xonly key is excluded from the scan set
                // rather than failing the whole block, matching
                // api_scan_outputs/api_session_scan's existing
                // filter-and-skip behavior for malformed entries.
                if let Ok(xonly) = XOnlyPublicKey::from_slice(xonly_bytes) {
                    vout_of.insert(xonly, vout);
                    outputs_to_check.push(xonly);
                }
            }

            let scanned = session
                .receiver
                .scan_transaction(&shared_secret, outputs_to_check)
                .ok()?;

            for (label, outputs) in scanned {
                let label_str = label.map(|l| l.as_string()).unwrap_or_else(|| "None".to_string());
                for (xonly, tweak_out) in outputs {
                    let vout = *vout_of.get(&xonly).unwrap_or(&0);
                    matches.push(serde_json::json!({
                        "height": height,
                        "txid": txid_hex,
                        "vout": vout,
                        "label": label_str,
                        "output_pubkey": xonly.to_string(),
                        "tweak": tweak_out.to_be_bytes().as_hex().to_string(),
                    }));
                }
            }
        }

        if matches.is_empty() {
            return Some(ptr_from_str("[]"));
        }
        let serialized = serde_json::to_string(&matches).ok()?;
        Some(ptr_from_str(&serialized))
    }));

    match result {
        Ok(Some(ptr)) => ptr,
        _ => std::ptr::null_mut(),
    }
}

/// Highest `blockchain.tweaks.subscribe` wire-protocol version this build's
/// decoder understands. `1` = JSON only (`api_scan_outputs`/`api_session_scan`).
/// `2` = the compact binary protocol (`api_session_scan_block_v2`), per
/// electrs-tweaks's `doc/tweaks_v2_protocol.md`. Client-side capability
/// negotiation must take `min(server-advertised, this)`, never the server's
/// offer alone, so a client can't attempt a version its own decoder can't
/// read.
#[no_mangle]
pub extern "C" fn api_max_wire_version() -> u32 {
    2
}

#[no_mangle]
pub extern "C" fn free_pointer(ptr: *mut c_char) {
    unsafe {
        if !ptr.is_null() {
            drop(CString::from_raw(ptr));
        }
    }
}
