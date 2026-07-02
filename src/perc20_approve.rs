use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha3::{Digest, Keccak256};
use ethabi::{encode as abi_encode, Token, Uint as EthUint};
use serde_json::Value;
use rand::RngCore;
use rand::rngs::OsRng;

// ── Baby JubJub twisted Edwards curve over BN254 Fr (port of BabyJubJub.sol) ──

fn bjj_fr() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap()
}
fn bjj_l() -> BigUint {
    BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041", 10).unwrap()
}
fn g_value() -> (BigUint, BigUint) {
    (BigUint::parse_bytes(b"17fd59f6a76603fa600c9b7a5ef1b693b699e1a3b99dd8388c6090614cbfbd81", 16).unwrap(),
     BigUint::parse_bytes(b"2e4f05547eb757a53ca2144eb3d906765944cc5d2aa42af14db8eeb7b383d396", 16).unwrap())
}
fn g_random() -> (BigUint, BigUint) {
    (BigUint::parse_bytes(b"27ce0892199f95ef98264f2b1c462f1f0c78c4a8889b2227cdff59b9cbc20318", 16).unwrap(),
     BigUint::parse_bytes(b"0b5cdda12f9788cd04b1eb41e026fb608d394b219b5c659313ea5a70f1262f81", 16).unwrap())
}
fn g_spend_auth() -> (BigUint, BigUint) {
    (BigUint::parse_bytes(b"1500e9f13e31bb51f59740ae2c7a904eca7ab98c964d4eabdf41f8384d3d45fe", 16).unwrap(),
     BigUint::parse_bytes(b"0a15846c8fab9380e66c443f85c8ac73656217d6e8008968a5d63b282d7ab167", 16).unwrap())
}

fn mulmod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint { (a * b) % m }
fn addmod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint { (a + b) % m }
fn submod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    let a = a % m; let b = b % m;
    if a >= b { a - b } else { a + m - b }
}

fn proj_double(x1: &BigUint, y1: &BigUint, z1: &BigUint) -> (BigUint, BigUint, BigUint) {
    let p = bjj_fr();
    let a = BigUint::from(168700u32);
    let b_ = mulmod(&addmod(x1, y1, &p), &addmod(x1, y1, &p), &p);
    let c_ = mulmod(x1, x1, &p);
    let dv = mulmod(y1, y1, &p);
    let e_ = mulmod(&a, &c_, &p);
    let f_ = addmod(&e_, &dv, &p);
    let h_ = mulmod(z1, z1, &p);
    let j_ = submod(&f_, &addmod(&h_, &h_, &p), &p);
    let x3 = mulmod(&submod(&b_, &addmod(&c_, &dv, &p), &p), &j_, &p);
    let y3 = mulmod(&f_, &submod(&e_, &dv, &p), &p);
    let z3 = mulmod(&f_, &j_, &p);
    (x3, y3, z3)
}

fn proj_add_affine(x1: &BigUint, y1: &BigUint, z1: &BigUint, x2: &BigUint, y2: &BigUint)
    -> (BigUint, BigUint, BigUint) {
    let p = bjj_fr();
    let a = BigUint::from(168700u32);
    let d = BigUint::from(168696u32);
    let av = z1.clone();
    let bv = mulmod(&av, &av, &p);
    let cv = mulmod(x1, x2, &p);
    let dv = mulmod(y1, y2, &p);
    let ev = mulmod(&mulmod(&d, &cv, &p), &dv, &p);
    let fv = submod(&bv, &ev, &p);
    let gv = addmod(&bv, &ev, &p);
    let cross = submod(&mulmod(&addmod(x1, y1, &p), &addmod(x2, y2, &p), &p), &addmod(&cv, &dv, &p), &p);
    let x3 = mulmod(&mulmod(&av, &fv, &p), &cross, &p);
    let dac = submod(&dv, &mulmod(&a, &cv, &p), &p);
    let y3 = mulmod(&mulmod(&av, &gv, &p), &dac, &p);
    let z3 = mulmod(&fv, &gv, &p);
    (x3, y3, z3)
}

fn proj_to_affine(x: BigUint, y: BigUint, z: BigUint) -> (BigUint, BigUint) {
    let p = bjj_fr();
    let z_inv = z.modpow(&(&p - BigUint::from(2u32)), &p);
    ((&x * &z_inv) % &p, (&y * &z_inv) % &p)
}

fn bjj_scalar_mul(bx: &BigUint, by: &BigUint, scalar: &BigUint) -> (BigUint, BigUint) {
    let scalar = scalar % bjj_l();
    let mut rx = BigUint::zero();
    let mut ry = BigUint::one();
    let mut rz = BigUint::one();
    for i in 0..254usize {
        let (nx, ny, nz) = proj_double(&rx, &ry, &rz);
        rx = nx; ry = ny; rz = nz;
        if ((&scalar >> (253 - i)) & BigUint::one()) == BigUint::one() {
            let (nx, ny, nz) = proj_add_affine(&rx, &ry, &rz, bx, by);
            rx = nx; ry = ny; rz = nz;
        }
    }
    proj_to_affine(rx, ry, rz)
}

fn bjj_point_add(x1: &BigUint, y1: &BigUint, x2: &BigUint, y2: &BigUint) -> (BigUint, BigUint) {
    let (x3, y3, z3) = proj_add_affine(x1, y1, &BigUint::one(), x2, y2);
    proj_to_affine(x3, y3, z3)
}
fn bjj_point_neg(x: &BigUint, y: &BigUint) -> (BigUint, BigUint) {
    let p = bjj_fr();
    (if x.is_zero() { BigUint::zero() } else { &p - x }, y.clone())
}

fn biguint_to_bytes32(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    out
}
fn biguint_to_eth_uint(n: &BigUint) -> EthUint { EthUint::from_big_endian(&biguint_to_bytes32(n)) }

// ── v1 sighashes (match SpendAuthSignature / BindingSignature at 518c0e1) ──────

fn sighash_bundle(chain_id: u64, pool: [u8; 20], nfs: &[[u8; 32]], cms: &[[u8; 32]],
                  value_balance: &BigUint, recipient_meta: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"PrivacyPool.bundle.v2");
    let mut cid = [0u8; 32]; cid[24..].copy_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&cid);
    buf.extend_from_slice(&pool);
    for nf in nfs { buf.extend_from_slice(nf); }
    for cm in cms { buf.extend_from_slice(cm); }
    buf.extend_from_slice(&biguint_to_bytes32(value_balance));
    buf.extend_from_slice(&recipient_meta);
    // v2 binds an executor (abi.encodePacked address = 20 bytes). The relayer only re-signs
    // permissionless ops (mint/approve/transfer), so executor = address(0). (Swap legs are
    // relayed verbatim from the prover, not re-signed here.)
    buf.extend_from_slice(&[0u8; 20]);
    Keccak256::digest(&buf).into()
}

fn sighash_action(chain_id: u64, pool: [u8; 20], nf_old: [u8; 32], cmx: [u8; 32], epk: [u8; 32],
                  enc_ct: &[u8], out_ct: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"SpendAuth.action.v2");
    let mut cid = [0u8; 32]; cid[24..].copy_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&cid);
    buf.extend_from_slice(&pool);
    buf.extend_from_slice(&nf_old);
    buf.extend_from_slice(&cmx);
    buf.extend_from_slice(&epk);
    let enc_hash: [u8; 32] = Keccak256::digest(enc_ct).into();
    let out_hash: [u8; 32] = Keccak256::digest(out_ct).into();
    buf.extend_from_slice(&enc_hash);
    buf.extend_from_slice(&out_hash);
    // v2 binds executor = address(0) for permissionless re-signed ops (see sighash_bundle).
    buf.extend_from_slice(&[0u8; 20]);
    Keccak256::digest(&buf).into()
}

fn schnorr_challenge(rx: &BigUint, ry: &BigUint, pkx: &BigUint, pky: &BigUint, sighash: &[u8; 32]) -> BigUint {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&biguint_to_bytes32(rx));
    buf.extend_from_slice(&biguint_to_bytes32(ry));
    buf.extend_from_slice(&biguint_to_bytes32(pkx));
    buf.extend_from_slice(&biguint_to_bytes32(pky));
    buf.extend_from_slice(sighash);
    BigUint::from_bytes_be(&Keccak256::digest(&buf)) % bjj_l()
}


fn bjj_sign(gx: &BigUint, gy: &BigUint, sk: &BigUint, pkx: &BigUint, pky: &BigUint,
            sighash: &[u8; 32]) -> [BigUint; 3] {
    let l = bjj_l();
    let mut seed = sighash.clone();
    let r = loop {
        OsRng.fill_bytes(&mut seed);
        let r = BigUint::from_bytes_be(&seed) % &l;
        if !r.is_zero() {
            break r;
        }
    };
    let (rx, ry) = bjj_scalar_mul(gx, gy, &r);
    let e = schnorr_challenge(&rx, &ry, pkx, pky, sighash);
    let s = (&r + &e * sk) % bjj_l();
    [rx, ry, s]
}

fn spend_auth_sig(chain_id: u64, pool: [u8; 20], nf_old: [u8; 32], cmx: [u8; 32], epk: [u8; 32],
                  enc_ct: &[u8], out_ct: &[u8], rsk: &BigUint, rk_x: &BigUint, rk_y: &BigUint) -> [BigUint; 3] {
    let sh = sighash_action(chain_id, pool, nf_old, cmx, epk, enc_ct, out_ct);
    let (gsx, gsy) = g_spend_auth();
    bjj_sign(&gsx, &gsy, rsk, rk_x, rk_y, &sh)
}

/// Combined binding sig for a value-neutral multi-action bundle: bvk = Σ cv_i (vbScalar = 0),
/// bsk = Σ rcv_i mod ℓ.
fn binding_sig_bundle(chain_id: u64, pool: [u8; 20], nfs: &[[u8; 32]], cmxs: &[[u8; 32]],
                      cvs: &[(BigUint, BigUint)], rcvs: &[BigUint]) -> [BigUint; 3] {
    let vb = BigUint::zero();
    let sh = sighash_bundle(chain_id, pool, nfs, cmxs, &vb, [0u8; 32]);
    let (mut bx, mut by) = cvs[0].clone();
    for cv in &cvs[1..] {
        let (x, y) = bjj_point_add(&bx, &by, &cv.0, &cv.1);
        bx = x; by = y;
    }
    let l = bjj_l();
    let bsk = rcvs.iter().fold(BigUint::zero(), |acc, r| (acc + r) % &l);
    let (grx, gry) = g_random();
    bjj_sign(&grx, &gry, &bsk, &bx, &by, &sh)
}

fn parse_dec(v: &Value) -> BigUint {
    BigUint::parse_bytes(v.as_str().expect("decimal string").as_bytes(), 10).expect("decimal")
}

/// Build one `BundleAction` ABI token from a prover fixture (v1 spend-auth sig); also returns the
/// `(cv, rcv, nf, cmx)` the bundle-level binding signature needs.
fn action_token_from_fixture(chain_id: u64, pool: [u8; 20], fixture: &Value)
    -> (Token, (BigUint, BigUint), BigUint, [u8; 32], [u8; 32]) {
    let proof = hex::decode(fixture["proof_hex"].as_str().unwrap()).unwrap();
    let pub_fields: Vec<BigUint> = fixture["pub_fields"].as_array().unwrap().iter().map(parse_dec).collect();
    let rcv = parse_dec(&fixture["rcv"]);
    let rsk = parse_dec(&fixture["rsk"]);
    let cmx_bytes = biguint_to_bytes32(&parse_dec(&fixture["cmx"]));
    let nf_bytes = biguint_to_bytes32(&parse_dec(&fixture["nf_old"]));
    let anchor_bytes = biguint_to_bytes32(&parse_dec(&fixture["anchor"]));
    let enc_ct = hex::decode(fixture["enc_ciphertext_hex"].as_str().unwrap()).unwrap();
    let out_ct = hex::decode(fixture["out_ciphertext_hex"].as_str().unwrap()).unwrap();
    let epk_raw = hex::decode(fixture["epk_hex"].as_str().unwrap()).unwrap();
    let mut epk_bytes = [0u8; 32];
    epk_bytes[32 - epk_raw.len()..].copy_from_slice(&epk_raw);

    let cv = (pub_fields[1].clone(), pub_fields[2].clone());
    let sasig = spend_auth_sig(chain_id, pool, nf_bytes, cmx_bytes, epk_bytes,
        &enc_ct, &out_ct, &rsk, &pub_fields[4], &pub_fields[5]);

    let pub_toks: Vec<Token> = pub_fields.iter().map(|f| Token::Uint(biguint_to_eth_uint(f))).collect();
    let sa_toks: Vec<Token> = sasig.iter().map(|s| Token::Uint(biguint_to_eth_uint(s))).collect();
    let action = Token::Tuple(vec![
        Token::FixedBytes(cmx_bytes.to_vec()),
        Token::Bytes(enc_ct),
        Token::Bytes(out_ct),
        Token::FixedBytes(epk_bytes.to_vec()),
        Token::FixedBytes(nf_bytes.to_vec()),
        Token::FixedBytes(anchor_bytes.to_vec()),
        Token::Bytes(proof),
        Token::FixedArray(pub_toks),
        Token::FixedArray(sa_toks),
    ]);
    (action, cv, rcv, nf_bytes, cmx_bytes)
}

/// Assemble the value-neutral approve `transfer((bytes,uint256[3]))` calldata from N action
/// fixtures (in order). Used as 2 actions (funding + delivery, when the input note exactly equals
/// the approved amount) or 3 (funding + change-to-owner + delivery, for a partial approve). One
/// combined binding signature over all actions (bsk = Σ rcv_i, vb = 0).
pub fn build_approve_transfer_calldata(chain_id: u64, pool: [u8; 20], fixtures: &[&Value]) -> Vec<u8> {
    let mut actions = Vec::with_capacity(fixtures.len());
    let mut cvs = Vec::with_capacity(fixtures.len());
    let mut rcvs = Vec::with_capacity(fixtures.len());
    let mut nfs = Vec::with_capacity(fixtures.len());
    let mut cmxs = Vec::with_capacity(fixtures.len());
    for f in fixtures {
        let (act, cv, rcv, nf, cmx) = action_token_from_fixture(chain_id, pool, f);
        actions.push(act);
        cvs.push(cv);
        rcvs.push(rcv);
        nfs.push(nf);
        cmxs.push(cmx);
    }

    let bsig = binding_sig_bundle(chain_id, pool, &nfs, &cmxs, &cvs, &rcvs);

    let actions_bytes = abi_encode(&[Token::Array(actions)]);
    let bsig_toks: Vec<Token> = bsig.iter().map(|s| Token::Uint(biguint_to_eth_uint(s))).collect();
    let privacy_call = Token::Tuple(vec![Token::Bytes(actions_bytes), Token::FixedArray(bsig_toks)]);

    let selector: [u8; 4] = Keccak256::digest(b"transfer((bytes,uint256[3]))")[..4].try_into().unwrap();
    let args = abi_encode(&[privacy_call]);
    [selector.as_slice(), &args].concat()
}

/// Parse a `0x`-prefixed 20-byte address hex into bytes.
pub fn parse_pool_addr(s: &str) -> Result<[u8; 20], String> {
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("pool hex: {e}"))?;
    raw.try_into().map_err(|_| "pool address must be 20 bytes".to_string())
}

// ── mint calldata (issuer; vb = amount | 1<<255) ─────────────────────────────

/// _vbScalar: sign-bit-encoded valueBalance → BJJ scalar. negative ⟹ ℓ − (|amt| % ℓ); else |amt|.
fn vb_scalar(vb: &BigUint) -> BigUint {
    let sign_bit: BigUint = BigUint::one() << 255usize;
    let negative = vb >= &sign_bit;
    let abs_amount = vb & (&sign_bit - BigUint::one());
    if negative && !abs_amount.is_zero() {
        let l = bjj_l();
        let r = &abs_amount % &l;
        if r.is_zero() { BigUint::zero() } else { &l - r }
    } else {
        abs_amount
    }
}

/// bvk = cv − vbScalar·G_VALUE  (single action).
fn compute_bvk(cv_x: &BigUint, cv_y: &BigUint, vb: &BigUint) -> (BigUint, BigUint) {
    let (gvx, gvy) = g_value();
    let (vbptx, vbpty) = bjj_scalar_mul(&gvx, &gvy, &vb_scalar(vb));
    let (neg_x, neg_y) = bjj_point_neg(&vbptx, &vbpty);
    bjj_point_add(cv_x, cv_y, &neg_x, &neg_y)
}

/// Single-action binding signature with a (possibly signed) value balance.
fn binding_sig_single(chain_id: u64, pool: [u8; 20], nf: [u8; 32], cmx: [u8; 32],
                      vb: &BigUint, cv_x: &BigUint, cv_y: &BigUint, rcv: &BigUint) -> [BigUint; 3] {
    let sh = sighash_bundle(chain_id, pool, &[nf], &[cmx], vb, [0u8; 32]);
    let (bvkx, bvky) = compute_bvk(cv_x, cv_y, vb);
    let (grx, gry) = g_random();
    bjj_sign(&grx, &gry, rcv, &bvkx, &bvky, &sh)
}

/// Assemble `mint(uint256,(bytes,uint256[3]))` calldata from a `/mint/prove` fixture.
/// Mint encodes a negative value balance: `vb = amount | (1<<255)`.
pub fn build_mint_calldata(chain_id: u64, pool: [u8; 20], amount_sats: u64, fixture: &Value) -> Vec<u8> {
    let (action, cv, rcv, nf, cmx) = action_token_from_fixture(chain_id, pool, fixture);
    let vb = BigUint::from(amount_sats) | (BigUint::one() << 255usize);
    let bsig = binding_sig_single(chain_id, pool, nf, cmx, &vb, &cv.0, &cv.1, &rcv);

    let actions_bytes = abi_encode(&[Token::Array(vec![action])]);
    let bsig_toks: Vec<Token> = bsig.iter().map(|s| Token::Uint(biguint_to_eth_uint(s))).collect();
    let privacy_call = Token::Tuple(vec![Token::Bytes(actions_bytes), Token::FixedArray(bsig_toks)]);

    let selector: [u8; 4] = Keccak256::digest(b"mint(uint256,(bytes,uint256[3]))")[..4].try_into().unwrap();
    let args = abi_encode(&[Token::Uint(EthUint::from(amount_sats)), privacy_call]);
    [selector.as_slice(), &args].concat()
}
