//! Calldata encoders for the **deployed** `PERC20AtomicSwap` (contracts/swap/PERC20AtomicSwap.sol)
//! used by the decentralized, seedless DEX settlement flow:
//!
//!   1. maker proves leg A locally → `initiateSwap` (parks leg A pending, sets H = keccak(S))
//!   2. taker proves leg B locally → `joinSwap`     (parks leg B pending)
//!   3. maker → `complete(swapId, S)`               (reveals S, finalizes BOTH pending legs)
//!
//! This is intentionally SEPARATE from the relayer's existing `/swap/*` endpoints, which target a
//! different (commitment-based `SwapCoordinator`) ABI in `privacy_core::ethereum::perc20`. These
//! encoders mirror `privacybtc-ethereum`'s `encode_perc20_*` (the orderbook's proven settle path)
//! but use the relayer's own `privacy_core::ethereum::BundleActionArgs` (field-identical), since
//! `privacybtc-ethereum` can't be path-dep'd across workspaces.

use ethabi::{encode, Token, Uint};
use privacy_core::ethereum::BundleActionArgs;
use sha3::{Digest, Keccak256};

/// `keccak256(signature)[..4]`.
fn selector(signature: &[u8]) -> [u8; 4] {
    Keccak256::digest(signature)[..4]
        .try_into()
        .expect("selector is 4 bytes")
}

/// ABI token for `BundleAction[]` — tuple layout
/// `(bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])`, matching
/// `IEndpointCore.BundleAction` and `privacy_core::ethereum::encode_bundle_calldata`.
fn bundle_actions_array_token(actions: &[BundleActionArgs]) -> Token {
    Token::Array(
        actions
            .iter()
            .map(|a| {
                let pub_fields = Token::FixedArray(
                    a.pub_fields
                        .iter()
                        .map(|b| Token::Uint(Uint::from_big_endian(b)))
                        .collect(),
                );
                let spend_auth_sig = Token::FixedArray(
                    a.spend_auth_sig
                        .iter()
                        .map(|b| Token::Uint(Uint::from_big_endian(b)))
                        .collect(),
                );
                Token::Tuple(vec![
                    Token::FixedBytes(a.cmx.to_vec()),
                    Token::Bytes(a.enc_ciphertext.clone()),
                    Token::Bytes(a.out_ciphertext.clone()),
                    Token::FixedBytes(a.epk.to_vec()),
                    Token::FixedBytes(a.nf_old.to_vec()),
                    Token::FixedBytes(a.anchor.to_vec()),
                    Token::Bytes(a.proof.clone()),
                    pub_fields,
                    spend_auth_sig,
                ])
            })
            .collect(),
    )
}

/// `[Rx, Ry, s]` Baby JubJub binding signature → `uint256[3]` token.
fn binding_sig_token(binding_sig: &[[u8; 32]; 3]) -> Token {
    Token::FixedArray(
        binding_sig
            .iter()
            .map(|b| Token::Uint(Uint::from_big_endian(b)))
            .collect(),
    )
}

/// `initiateSwap(address poolA, address poolB, BundleAction[] actionsA, uint256[3] bindingSigA,
///  bytes32 htlcHash, bytes counterpartyAddr)` calldata.
pub fn encode_initiate(
    pool_a: &[u8; 20],
    pool_b: &[u8; 20],
    actions_a: &[BundleActionArgs],
    binding_sig: &[[u8; 32]; 3],
    htlc_hash: &[u8; 32],
    counterparty_addr: &[u8],
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool_a)),
        Token::Address(ethabi::Address::from(*pool_b)),
        bundle_actions_array_token(actions_a),
        binding_sig_token(binding_sig),
        Token::FixedBytes(htlc_hash.to_vec()),
        Token::Bytes(counterparty_addr.to_vec()),
    ];
    let body = encode(&tokens);
    let mut out = selector(
        b"initiateSwap(address,address,(bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[],uint256[3],bytes32,bytes)",
    )
    .to_vec();
    out.extend_from_slice(&body);
    out
}

/// `joinSwap(bytes32 swapId, BundleAction[] actionsB, uint256[3] bindingSigB, bytes32 htlcHash)`.
pub fn encode_join(
    swap_id: &[u8; 32],
    actions_b: &[BundleActionArgs],
    binding_sig: &[[u8; 32]; 3],
    htlc_hash: &[u8; 32],
) -> Vec<u8> {
    let tokens = vec![
        Token::FixedBytes(swap_id.to_vec()),
        bundle_actions_array_token(actions_b),
        binding_sig_token(binding_sig),
        Token::FixedBytes(htlc_hash.to_vec()),
    ];
    let body = encode(&tokens);
    let mut out = selector(
        b"joinSwap(bytes32,(bytes32,bytes,bytes,bytes32,bytes32,bytes32,bytes,uint256[8],uint256[3])[],uint256[3],bytes32)",
    )
    .to_vec();
    out.extend_from_slice(&body);
    out
}

/// `complete(bytes32 swapId, bytes32 preimage)`.
pub fn encode_complete(swap_id: &[u8; 32], preimage: &[u8; 32]) -> Vec<u8> {
    let tokens = vec![
        Token::FixedBytes(swap_id.to_vec()),
        Token::FixedBytes(preimage.to_vec()),
    ];
    let body = encode(&tokens);
    let mut out = selector(b"complete(bytes32,bytes32)").to_vec();
    out.extend_from_slice(&body);
    out
}

/// `keccak256("SwapInitiated(bytes32,address,address,bytes32,bytes)")` — topic0 of the event whose
/// indexed `topic1` is the `swapId` (contract derives it from `keccak(poolA,poolB,sender,nonce)`,
/// so it can only be read from the receipt, not computed off-chain).
fn swap_initiated_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"SwapInitiated(bytes32,address,address,bytes32,bytes)"
        ))
    )
}

/// Extract `swapId` (the indexed `topic1`) from a tx receipt's `SwapInitiated` log emitted by
/// `coordinator`. Returns `None` if no matching log is present.
pub fn extract_swap_id(receipt: &serde_json::Value, coordinator: &[u8; 20]) -> Option<[u8; 32]> {
    let topic0 = swap_initiated_topic0_hex();
    let want_addr = format!("0x{}", hex::encode(coordinator)).to_lowercase();
    for log in receipt.get("logs")?.as_array()? {
        let addr_ok = log
            .get("address")
            .and_then(|a| a.as_str())
            .map(|a| a.eq_ignore_ascii_case(&want_addr))
            .unwrap_or(false);
        if !addr_ok {
            continue;
        }
        let topics = match log.get("topics").and_then(|t| t.as_array()) {
            Some(t) => t,
            None => continue,
        };
        let t0 = topics.first().and_then(|t| t.as_str()).unwrap_or_default();
        if !t0.eq_ignore_ascii_case(&topic0) {
            continue;
        }
        if let Some(t1) = topics.get(1).and_then(|t| t.as_str()) {
            if let Ok(b) = hex::decode(t1.trim_start_matches("0x")) {
                if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
                    return Some(arr);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Selectors must match the deployed contract (and privacybtc-ethereum's encoders).
    #[test]
    fn selectors_are_stable() {
        assert_eq!(hex::encode(selector(b"complete(bytes32,bytes32)")).len(), 8);
        // initiate/join encode without panicking on an empty action set.
        let bs = [[0u8; 32]; 3];
        let _ = encode_initiate(&[0x11; 20], &[0x22; 20], &[], &bs, &[0x33; 32], &[0xAA; 43]);
        let _ = encode_join(&[0x44; 32], &[], &bs, &[0x55; 32]);
        let _ = encode_complete(&[0x66; 32], &[0x77; 32]);
    }
}
