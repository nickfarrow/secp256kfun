#![allow(missing_docs)]
//! Blind Schnorr Signatures
//!
//! Folllowing https://suredbits.com/schnorr-applications-blind-signatures/
//!

use crate::fun::rand_core::{CryptoRng, RngCore};
use crate::{Message, Schnorr};
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    s, Point, Scalar, G,
};

pub fn create_blindings<'a, H: Digest<OutputSize = U32> + Clone, NG, R: RngCore + CryptoRng>(
    nonce: Point,
    public_key: Point,
    message: Message,
    schnorr: Schnorr<H, NG>,
    rng: &mut R,
) -> (Point, Point, Scalar, Scalar, Scalar, Scalar) {
    let alpha = Scalar::random(rng);
    let t = Scalar::random(rng);
    let beta = Scalar::random(rng);

    // rename blinded to tweaked
    let blinded_public_key = g!({ public_key } + t * G)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    let blinded_nonce = g!(nonce + alpha * G + beta * public_key)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    let blinded_challenge = s!({
        schnorr.challenge(
            blinded_nonce.to_xonly(),
            blinded_public_key.to_xonly(),
            message,
        )
    } + beta)
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

#[derive(Debug)]
pub struct Blinder {
    pubnonce: Point,
    public_key: Point,
    challenge: Scalar,
    alpha: Scalar,
    beta: Scalar,
    t: Scalar,
}

impl Blinder {
    pub fn blind<H: Digest<OutputSize = U32> + Clone, R: RngCore + CryptoRng>(
        pubnonce: Point,
        public_key: Point,
        message: Message,
        schnorr: Schnorr<H>,
        rng: &mut R,
    ) -> Self {
        let (blinded_public_key, blinded_nonce, blinded_challenge, alpha, t, beta) =
            create_blindings(pubnonce, public_key, message, schnorr, rng);

        Blinder {
            public_key: blinded_public_key,
            pubnonce: blinded_nonce,
            challenge: blinded_challenge,
            alpha,
            t,
            beta,
        }
    }

    pub fn unblind(&self, blinded_signature: Scalar<Public, Zero>) -> Scalar<Public, Zero> {
        s!(blinded_signature + self.alpha).mark::<Public>()
    }
}

pub fn blind_sign(secret: &Scalar, nonce: Scalar, blind_challenge: Scalar) -> Scalar<Public, Zero> {
    s!(nonce + blind_challenge * secret).mark::<Public>()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Message, Schnorr, Signature};
    use secp256kfun::{g, Scalar, G};
    use sha2::Sha256;

    // proptest! {
    // #[test]
    // fn blind_unblind(public_key in any::<XOnly>(), nonce in any::<Point>(),
    // need rng again..

    #[test]
    fn test_blind_unblind() {
        let schnorr = Schnorr::<Sha256, _>::new(());
        // This is the secret & public key of the party blindly signing
        let secret = Scalar::random(&mut rand::thread_rng());
        let public_key = g!(secret * G).normalize();

        // Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
        let nonce = Scalar::random(&mut rand::thread_rng());
        // The blind signer sends a nonce public nonce
        let pub_nonce = g!(nonce * G).normalize();

        let message =
            Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

        // we calculate a blinded challenge and send to the signer
        let blinded = Blinder::blind(
            pub_nonce,
            public_key,
            message,
            schnorr.clone(),
            &mut rand::thread_rng(),
        );

        // blind signer uses this challenge to sign under their secret key
        let blind_signature = blind_sign(&secret, nonce, blinded.challenge.clone());

        // we recieve the blinded signature from the signer, and unblind it
        let unblinded_signature = Signature {
            s: blinded.unblind(blind_signature),
            R: blinded.pubnonce.to_xonly(),
        };

        dbg!(&blinded);
        dbg!(&unblinded_signature);
        // This signature is valid under the signer's public key
        let (verification_public_key, negated) = public_key.into_point_with_even_y();
        assert!(schnorr.verify(&verification_public_key, message, &unblinded_signature));
    }
}
