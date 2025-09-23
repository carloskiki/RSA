use crypto_bigint::BoxedUint;
use sha2::{Digest, Sha256, Sha384, Sha512};
use verifiable_random_function::{Prover, Verifier};

use crate::{algorithms, RsaPrivateKey, RsaPublicKey};

pub struct Proof {
    inner: BoxedUint,
}

macro_rules! impl_vrf {
    ($($hash:ty, $suite:literal)*) => {
        $(impl verifiable_random_function::Proof<$hash> for Proof {
            fn to_hash(&self) -> digest::Output<$hash> {
                algorithms::vrf::proof_to_hash::<$hash>(&[$suite], &self.inner.to_be_bytes())
            }
        }
        
        impl Prover<$hash> for RsaPrivateKey {
            type Proof = Proof;

            fn prove(&self, alpha: &[u8]) -> Self::Proof {
                Proof {
                    inner: algorithms::vrf::prove(&mut <$hash>::new(), self, alpha, &[$suite]),
                }
            }
        }

        impl Verifier<$hash> for RsaPublicKey {
            type Proof = Proof;

            fn verify(&self, alpha: &[u8], pi: &Self::Proof) -> bool {
                algorithms::vrf::verify(&mut <$hash>::new(), self, alpha, &pi.inner, &[$suite])
            }
        })*
    }
}

impl_vrf! {
    Sha256, 0x01
    Sha384, 0x02
    Sha512, 0x03
}
