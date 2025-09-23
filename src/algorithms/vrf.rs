use core::convert::Infallible;

use crypto_bigint::BoxedUint;
use digest::{Digest, DynDigest, Output};

use crate::{
    algorithms::mgf::mgf1_xor,
    hazmat::{rsa_decrypt, rsa_encrypt},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};

pub fn prove(
    digest: &mut impl DynDigest,
    k: &RsaPrivateKey,
    alpha_string: &[u8],
    suite_string: &[u8],
) -> BoxedUint {
    // 1. mgf_domain_separator = 0x01
    const MGF_DOMAIN_SEPARATOR: &[u8] = &[1];
    // 2. EM = MGF1(suite_string || mgf_domain_separator || MGF_salt || alpha_string, k - 1)
    let mut em = vec![0u8; k.size() - 1];
    let seed = [
        suite_string,
        MGF_DOMAIN_SEPARATOR,
        &(k.size() as u32).to_be_bytes(),
        &k.n_bytes(),
        alpha_string,
    ]
    .concat();
    mgf1_xor(&mut em, digest, &seed);
    // 3. m = OS2IP(EM)
    let m = BoxedUint::from_be_slice(&em, k.n_bits_precision())
        .expect("em is `k.size() - 1` bytes long");
    // 4. s = RSASP1(K, m)
    // 5. pi_string = I2OSP(s, k)
    // 6. Output pi_string
    struct NoRng;
    impl rand_core::TryRngCore for NoRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }
    impl rand_core::TryCryptoRng for NoRng {}
    rsa_decrypt::<NoRng>(None, k, &m).expect("m < n since em is `k.size() - 1` bytes long")
}

pub fn proof_to_hash<D>(suite_string: &[u8], pi_string: &[u8]) -> Output<D>
where
    D: Digest,
{
    const PROOF_TO_HASH_DOMAIN_SEPARATOR: &[u8] = &[2];
    let mut digest = D::new();
    digest.update(suite_string);
    digest.update(PROOF_TO_HASH_DOMAIN_SEPARATOR);
    digest.update(pi_string);
    digest.finalize()
}

pub fn verify(
    digest: &mut impl DynDigest,
    k: &RsaPublicKey,
    alpha_string: &[u8],
    pi: &BoxedUint,
    suite_string: &[u8],
) -> bool {
    // 2. m = RSAVP1((n, e), s) -- if RSAVP1 returns "signature representative out of range", output "INVALID" and stop
    let m = rsa_encrypt(k, pi).expect("always returns `Ok`");
    // 3. mgf_domain_separator = 0x01
    const MGF_DOMAIN_SEPARATOR: &[u8] = &[1];
    // 4. EM' = MGF1(suite_string || mgf_domain_separator || MGF_salt || alpha_string, k - 1)
    let mut em_prime = vec![0u8; k.n().as_ref().bits() as usize / 8 - 1];
    let seed = [
        suite_string,
        MGF_DOMAIN_SEPARATOR,
        &(k.size() as u32).to_be_bytes(),
        &k.n_bytes(),
        alpha_string,
    ]
    .concat();
    mgf1_xor(&mut em_prime, digest, &seed);
    // 5. m' = OS2IP(EM')
    let m_prime = BoxedUint::from_be_slice(&em_prime, k.n_bits_precision()).expect("em' is `k.size() - 1` bytes long");
    // 6. If m and m' are equal, output ("VALID", RSAFDHVRF_proof_to_hash(pi_string)); else output "INVALID"
    m == m_prime
}
