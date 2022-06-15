//! Blind Schnorr Signatures
//!
//! Folllowing https://suredbits.com/schnorr-applications-blind-signatures/
//!

use crate::fun::rand_core::{CryptoRng, RngCore};
use crate::{adaptor::EncryptedSignature, musig::Nonce, Message, Schnorr, Signature, Vec};
use secp256kfun::digest::{Reset, Update};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::NonceGen,
    s, Point, Scalar, XOnly, G,
};

pub fn create_blindings<'a, H: Digest<OutputSize = U32> + Clone, NG, R: RngCore + CryptoRng>(
    nonce: XOnly,
    public_key: XOnly,
    message: Message,
    schnorr: Schnorr<H, NG>,
    rng: &mut R,
) -> (XOnly, XOnly, Scalar, Scalar, Scalar, Scalar) {
    let alpha = Scalar::random(rng);
    let t = Scalar::random(rng);
    let beta = Scalar::random(rng);

    let blinded_public_key = g!({ public_key.to_point() } + t * G)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random")
        .to_xonly();
    let blinded_nonce = g!({ nonce.to_point() } + alpha * G)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random")
        .to_xonly();
    let blinded_challenge =
        s!({ schnorr.challenge(blinded_nonce, blinded_public_key, message) } + beta)
            .mark::<NonZero>()
            .expect("added tweak is random");
    (
        blinded_public_key,
        blinded_nonce,
        blinded_challenge,
        alpha,
        t,
        beta,
    )
}

pub struct Blinder {
    blinded_nonce: XOnly,
    blinded_public_key: XOnly,
    blinded_challenge: Scalar,
    // message: Message<'a>,
    alpha: Scalar,
    beta: Scalar,
    t: Scalar,
    unblinded_nonce: XOnly,
    unblinded_public_key: XOnly,
}

impl Blinder {
    pub fn blind<H: Digest<OutputSize = U32> + Clone, R: RngCore + CryptoRng>(
        nonce: XOnly,
        public_key: XOnly,
        message: Message,
        schnorr: Schnorr<H>,
        rng: &mut R,
    ) -> Self {
        let (blinded_public_key, blinded_nonce, blinded_challenge, alpha, t, beta) =
            create_blindings(nonce, public_key, message, schnorr, rng);

        Blinder {
            blinded_challenge,
            blinded_nonce,
            blinded_public_key,
            alpha,
            beta,
            t,
            unblinded_nonce: nonce,
            unblinded_public_key: public_key,
        }
    }
}

pub struct Unblinder {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fun::rand_core::{CryptoRng, RngCore};
    use crate::{adaptor::EncryptedSignature, musig::Nonce, Message, Schnorr, Signature, Vec};
    use secp256kfun::digest::{Reset, Update};
    use secp256kfun::nonce::Deterministic;
    use secp256kfun::{
        derive_nonce,
        digest::{generic_array::typenum::U32, Digest},
        g,
        hash::{HashAdd, Tagged},
        marker::*,
        nonce::NonceGen,
        s, Point, Scalar, XOnly, G,
    };
    use sha2::Sha256;

    // proptest! {
    // #[test]
    // fn blind_unblind(public_key in any::<XOnly>(), nonce in any::<Point>(),
    // need rng again..

    #[test]
    fn test_blind_unblind() {
        // let schnorr = crate::test_instance!();
        let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default())
        let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));

        // Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
        let nonce = Scalar::random(&mut rand::thread_rng());
        let pub_nonce = g!(nonce * G).normalize().to_xonly();

        let message =
            Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

        let blinded = Blinder::blind(
            pub_nonce,
            keypair.public_key(),
            message,
            schnorr,
            &mut rand::thread_rng(),
        );
    }
}
