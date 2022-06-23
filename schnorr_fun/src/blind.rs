#![allow(missing_docs)]
// #![allow(unused)]
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
    nonce: Point<EvenY>,
    public_key: Point,
    message: Message,
    schnorr: Schnorr<H, NG>,
    rng: &mut R,
) -> (Point, Point, Scalar, Scalar, Scalar, Scalar, bool, bool) {
    let mut alpha = Scalar::random(rng);
    let mut t = Scalar::random(rng);
    let mut beta = Scalar::random(rng);

    let tweaked_pubkey = g!(public_key + t * G)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    let tweaked_pubkey_needs_negation = !tweaked_pubkey.is_y_even();
    let tweaked_pubkey = tweaked_pubkey.conditional_negate(tweaked_pubkey_needs_negation);

    let blinded_nonce = g!(nonce + alpha * G + beta * tweaked_pubkey)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    let blinded_nonce_needs_negation = !blinded_nonce.is_y_even();
    let blinded_nonce = blinded_nonce.conditional_negate(blinded_nonce_needs_negation);
    alpha.conditional_negate(blinded_nonce_needs_negation);
    beta.conditional_negate(blinded_nonce_needs_negation);
    t.conditional_negate(tweaked_pubkey_needs_negation);

    let blinded_challenge =
        s!(
            { schnorr.challenge(blinded_nonce.to_xonly(), tweaked_pubkey.to_xonly(), message,) }
                + beta
        )
        .mark::<NonZero>()
        .expect("added tweak is random");

    (
        tweaked_pubkey,
        blinded_nonce,
        blinded_challenge,
        alpha,
        t,
        beta,
        tweaked_pubkey_needs_negation,
        blinded_nonce_needs_negation,
    )
}

pub fn unblind_signature(
    blinded_signature: Scalar<Public, Zero>,
    alpha: &Scalar<Secret, NonZero>,
    challenge: &Scalar<Secret, NonZero>,
    tweak: &Scalar<Secret, NonZero>,
) -> Scalar<Public, Zero> {
    s!(blinded_signature + alpha + challenge * tweak).mark::<Public>()
}

#[derive(Debug)]
pub struct Blinder {
    tweaked_pubkey: Point,
    pubnonce: Point,
    challenge: Scalar,
    alpha: Scalar,
    beta: Scalar,
    t: Scalar,
    pubkey_needs_negation: bool,
    nonce_needs_negation: bool,
}

impl Blinder {
    pub fn blind<H: Digest<OutputSize = U32> + Clone, R: RngCore + CryptoRng>(
        pubnonce: Point<EvenY>,
        public_key: Point,
        message: Message,
        schnorr: Schnorr<H>,
        rng: &mut R,
    ) -> Self {
        let (
            tweaked_pubkey,
            blinded_nonce,
            blinded_challenge,
            alpha,
            t,
            beta,
            pubkey_needs_negation,
            nonce_needs_negation,
        ) = create_blindings(pubnonce, public_key, message, schnorr, rng);

        Blinder {
            tweaked_pubkey,
            pubnonce: blinded_nonce,
            challenge: blinded_challenge,
            alpha,
            t,
            beta,
            pubkey_needs_negation,
            nonce_needs_negation,
        }
    }

    pub fn unblind(&self, blinded_signature: Scalar<Public, Zero>) -> Scalar<Public, Zero> {
        unblind_signature(blinded_signature, &self.alpha, &self.challenge, &self.t)
    }
}

pub fn blind_sign(
    secret: &Scalar,
    nonce: &mut Scalar,
    blind_challenge: Scalar,
    needs_negation: bool,
    nonce_needs_negation: bool,
) -> Scalar<Public, Zero> {
    let mut negated_blind_challenge = blind_challenge.clone();
    negated_blind_challenge.conditional_negate(needs_negation);
    nonce.conditional_negate(nonce_needs_negation);

    let sig = s!({ nonce } + negated_blind_challenge * secret).mark::<Public>();
    sig
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
        // This is the secret & public key of the party that will blindly sign a message
        let secret = Scalar::random(&mut rand::thread_rng());
        let public_key = g!(secret * G).normalize();

        // TODO: Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
        let mut nonce = Scalar::random(&mut rand::thread_rng());
        // The blind signer sends a public nonce to the user
        let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
        nonce.conditional_negate(nonce_negated);

        let message = Message::<Public>::plain("test", b"new ");

        // Using this nonce, we calculate a blinded public key, nonce, and challenge which
        // the server will sign.
        let blind_session = Blinder::blind(
            pub_nonce,
            public_key,
            message,
            schnorr.clone(),
            &mut rand::thread_rng(),
        );

        dbg!(
            blind_session.pubkey_needs_negation,
            blind_session.nonce_needs_negation,
        );

        // We send the challenge, (& currently two needs negations...) to the signing server
        // The blind signer signs under their secret key and original nonce
        let blind_signature = blind_sign(
            &secret,
            &mut nonce.clone(),
            blind_session.challenge.clone(),
            blind_session.pubkey_needs_negation,
            blind_session.nonce_needs_negation,
        );

        // we recieve the blinded signature from the signer, and unblind it revlealing
        // an uncorrelated signature for the message that is valid under the tweaked pubkey.
        // The server has also not seen the nonce.
        let unblinded_signature = Signature {
            s: blind_session.unblind(blind_signature),
            R: blind_session.pubnonce.to_xonly(),
        };

        let (verification_pubkey, _) = blind_session.tweaked_pubkey.into_point_with_even_y();
        assert!(schnorr.verify(&verification_pubkey, message, &unblinded_signature));
    }
}
