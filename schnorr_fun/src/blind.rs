#![allow(missing_docs)]
#![allow(unused)]
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
    let t = Scalar::random(rng);
    let mut beta = Scalar::random(rng);

    // rename blinded to tweaked
    // let blinded_public_key = g!(public_key + t * G)
    //     .normalize()
    //     .mark::<NonZero>()
    //     .expect("added tweak is random");

    dbg!(public_key.is_y_even());
    let public_key_needs_negation = !public_key.is_y_even();
    let blinded_public_key = public_key.conditional_negate(public_key_needs_negation);

    let blinded_nonce = g!(nonce + alpha * G + beta * blinded_public_key)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    dbg!(blinded_nonce);
    let blinded_nonce_needs_negation = !blinded_nonce.is_y_even();
    let blinded_nonce = blinded_nonce.conditional_negate(blinded_nonce_needs_negation);
    alpha.conditional_negate(blinded_nonce_needs_negation);
    beta.conditional_negate(blinded_nonce_needs_negation);
    dbg!(blinded_nonce);

    dbg!(public_key_needs_negation, blinded_nonce_needs_negation);

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
        public_key_needs_negation,
        blinded_nonce_needs_negation,
    )
}

#[derive(Debug)]
pub struct Blinder {
    pubnonce: Point,
    public_key: Point,
    challenge: Scalar,
    alpha: Scalar,
    // beta: Scalar,
    // t: Scalar,
    needs_negation: bool,
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
            blinded_public_key,
            blinded_nonce,
            blinded_challenge,
            alpha,
            t,
            beta,
            needs_negation,
            nonce_needs_negation,
        ) = create_blindings(pubnonce, public_key, message, schnorr, rng);

        Blinder {
            public_key: blinded_public_key,
            pubnonce: blinded_nonce,
            challenge: blinded_challenge,
            alpha,
            // t,
            // beta,
            needs_negation,
            nonce_needs_negation,
        }
    }

    pub fn unblind(&self, blinded_signature: Scalar<Public, Zero>) -> Scalar<Public, Zero> {
        s!(blinded_signature + self.alpha).mark::<Public>()
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
        // This is the secret & public key of the party blindly signing
        let secret = Scalar::random(&mut rand::thread_rng());
        let public_key = g!(secret * G).normalize();

        // Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
        let mut nonce = Scalar::random(&mut rand::thread_rng());
        // The blind signer sends a nonce public nonce
        let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
        nonce.conditional_negate(nonce_negated);

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
        let blind_signature = blind_sign(
            &secret,
            &mut nonce.clone(),
            blinded.challenge.clone(),
            blinded.needs_negation,
            blinded.nonce_needs_negation,
        );

        // we recieve the blinded signature from the signer, and unblind it
        let unblinded_signature = Signature {
            s: blinded.unblind(blind_signature),
            R: blinded.pubnonce.to_xonly(),
        };

        let (verification_public_key, flippy) = blinded.public_key.into_point_with_even_y();

        dbg!(flippy);

        assert!(schnorr.verify(&verification_public_key, message, &unblinded_signature));

        // let (eveny_nonce, _) = blinded.pubnonce.into_point_with_even_y();
        // assert_eq!(
        //     schnorr
        //         .anticipate_signature(&verification_public_key, &eveny_nonce, message)
        //         .normalize(),
        //     g!(unblinded_signature.s * G).normalize()
        // );
    }
}
