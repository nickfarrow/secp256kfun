//! In FROST, multiple parties cooperatively generate a single joint public key ([`FrostKey`]) for
//! creating Schnorr signatures. Unlike in [`musig`], only some threshold `t` of the `n` signers are
//! required to generate a signature under the key (rather than all `n`).
//!
//! This implementation has **not yet** been made compatible with other existing FROST
//! implementations (notably [secp256k1-zkp]).
//!
//! The original scheme was introduced in *[FROST: Flexible Round-Optimized Schnorr Threshold
//! Signatures]*. A more satisfying security proof was provided in *[Security of Multi- and Threshold
//! Signatures]*.
//!
//! > ⚠ At this stage this implementation is for API exploration purposes only. The way it is
//! currently implemented is not proven secure.
//!
//! [FROST: Flexible Round-Optimized Schnorr Threshold Signatures]: <https://eprint.iacr.org/2020/852.pdf>
//! [secp256k1-zkp]: <https://github.com/ElementsProject/secp256k1-zkp/pull/138>
//! [Security of Multi- and Threshold Signatures]: <https://eprint.iacr.org/2021/1375.pdf>
//! [`musig`]: crate::musig
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{
//!     frost::{self, Frost, ScalarPoly},
//!     Schnorr,
//!     Message,
//!     nonce::Deterministic,
//!     fun::marker::Public
//! };
//! use schnorr_fun::fun::Scalar;
//! use sha2::Sha256;
//! // use sha256 with deterministic nonce generation -- be careful!
//! let proto = frost::new_with_deterministic_nonces::<Sha256>();
//! // use synthetic nonces with randomness from ThredRng -- harder to make a mistake.
//! let proto = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
//! let mut rng = rand::thread_rng();
//! // Usually we start with an existing secret key
//! let static_secret_key = Scalar::random(&mut rng);
//! // Start key generation of a frost key with a threshold of two. each participant uses a secret
//! // scalar to derive a random scalar polynomial with two coefficients.
//! let threshold = 2;
//! let scalar_poly = proto.new_scalar_poly(static_secret_key, threshold, b"frost-unique-id");
//! # let scalar_poly2 = proto.new_scalar_poly(Scalar::random(&mut rng), threshold, b"frost-unique-id");
//! # let scalar_poly3 = proto.new_scalar_poly(Scalar::random(&mut rng), threshold, b"frost-unique-id");
//! // share our public point poly, and receive the point polys from other participants
//! # let point_poly2 = scalar_poly2.to_point_poly();
//! # let point_poly3 = scalar_poly3.to_point_poly();
//! let point_polys = vec![scalar_poly.to_point_poly(), point_poly2, point_poly3];
//! // create secret shares and proofs-of-possession using our secret scalar polynomial
//! let keygen = proto.new_keygen(point_polys).expect("something wrong with what was provided by other parties");
//! let (shares, pop) = proto.create_shares(&keygen, scalar_poly);
//! # let (shares2, pop2) = proto.create_shares(&keygen, scalar_poly2);
//! # let (shares3, pop3) = proto.create_shares(&keygen, scalar_poly3);
//! // send the secret share at index i and all proofs-of-possession to each other participant i,
//! // and receive our shares from each other participant as well as their proofs-of-possession.
//! let received_shares = vec![shares[0].clone(), shares2[0].clone(), shares3[0].clone()];
//! # let received_shares3 = vec![shares[2].clone(), shares2[2].clone(), shares3[2].clone()];
//! let proofs_of_possession = vec![pop, pop2, pop3];
//! // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
//! // and calculate our long-lived secret share of the joint FROST key.
//! let (secret_share, frost_key) = proto
//!     .finish_keygen_to_xonly(
//!         keygen.clone(),
//!         0,
//!         received_shares,
//!         proofs_of_possession.clone(),
//!     )
//!     .unwrap();
//! # let (secret_share3, _frost_key3) = proto
//! #    .finish_keygen_to_xonly(
//! #        keygen.clone(),
//! #        2,
//! #        received_shares3,
//! #        proofs_of_possession.clone(),
//! #    )
//! #    .unwrap();
//! // signing parties must use a common set of nonces when creating signature shares.
//! // nonces can be derived from a session id which is created from publicly known values.
//! let verification_shares_bytes: Vec<_> = frost_key
//!     .verification_shares()
//!     .map(|share| share.to_bytes())
//!     .collect();
//! // create a unique session id
//! let sid = [
//!     verification_shares_bytes.concat().as_slice(),
//!     b"frost-very-unique-id".as_slice(),
//!     b"0".as_slice(),
//! ]
//! .concat();
//! # let sid3 = [
//! #    verification_shares_bytes.concat().as_slice(),
//! #    b"frost-very-unique-id".as_slice(),
//! #    b"2".as_slice(),
//! # ]
//! # .concat();
//! // generate nonces for this signing session
//! let nonce = proto.gen_nonce(&secret_share, &sid, Some(frost_key.public_key().normalize()), None);
//! # let nonce3 = proto.gen_nonce(&secret_share3, &sid3, Some(frost_key.public_key().normalize()), None);
//! // share your public nonce with the other signing participant(s)
//! # let received_nonce3 = nonce3.public();
//! // receive public nonces from other signers with their participant index
//! let nonces = vec![(0, nonce.public()), (2, received_nonce3)];
//! # let nonces3 = vec![(0, nonce.public()), (2, received_nonce3)];
//! // start a sign session with these nonces for a message
//! let message =  Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! let session = proto.start_sign_session(&frost_key, nonces, message);
//! # let session3 = proto.start_sign_session(&frost_key, nonces3, message);
//! // create a partial signature using our secret share and secret nonce
//! let sig = proto.sign(&frost_key, &session, 0, &secret_share, nonce);
//! # let sig3 = proto.sign(&frost_key, &session3, 2, &secret_share3, nonce3);
//! // receive the partial signature(s) from the other participant(s) and verify
//! assert!(proto.verify_signature_share(&frost_key, &session, 2, sig3));
//! // combine signature shares into a single signature that is valid under the FROST key
//! let combined_sig = proto.combine_signature_shares(&frost_key, &session, vec![sig, sig3]);
//! assert!(proto.schnorr.verify(
//!     &frost_key.public_key(),
//!     message,
//!     &combined_sig
//! ));
//! ```
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{Message, Schnorr, Signature, Vec};
use core::{iter, num::NonZeroU32};
use rand_core::RngCore;
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::{self, AddTag, NonceGen},
    rand_core, s, Point, Scalar, G,
};
use std::collections::BTreeMap;

/// The FROST context.
///
/// Type parametres:
///
/// - `H`: hash for challenges, keygen_id, and binding coefficient.
/// - `NG`: hash for nonce generation when signing.
#[derive(Clone)]
pub struct Frost<H, NG> {
    /// The instance of the Schnorr signature scheme.
    pub schnorr: Schnorr<H, NG>,
    /// The hash used in the binding coefficient of the frost key.
    binding_hash: H,
    /// The hash used to generate the keygen_id.
    keygen_id_hash: H,
}

impl<H: Default + Tagged + Digest<OutputSize = U32>, NG: Default + AddTag> Default
    for Frost<H, NG>
{
    fn default() -> Self {
        Frost::new(Schnorr::default())
    }
}

impl<H: Tagged, NG> Frost<H, NG> {
    /// Generate a new Frost context from a Schnorr context.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{frost::Frost, nonce::Deterministic, Schnorr};
    /// use sha2::Sha256;
    /// let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
    /// let frost = Frost::new(schnorr);
    /// ```
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            schnorr,
            binding_hash: H::default().tagged(b"frost/binding"),
            keygen_id_hash: H::default().tagged(b"frost/keygenid"),
        }
    }
}

/// A participant's secret polynomial with `t` random coefficients.
#[derive(Clone, Debug, PartialEq)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
    /// Evaluate the scalar polynomial at position x.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{frost::ScalarPoly, fun::s};
    /// let scalar_poly = ScalarPoly::random(3, &mut rand::thread_rng());
    /// let value_at_1 = scalar_poly.eval(s!(1));
    /// let value_at_2 = scalar_poly.eval(s!(2));
    /// ```
    pub fn eval(&self, x: Scalar<impl Secrecy, impl ZeroChoice>) -> Scalar<Secret, Zero> {
        let mut xpow = s!(1).public().mark_zero();
        let mut sum = self.0[0].clone().mark_zero();

        for coeff in &self.0[1..] {
            xpow *= &x;
            sum += s!(xpow * coeff);
        }

        sum
    }

    /// Create a point polynomial by multiplying each coefficient by `G`
    pub fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    /// Create a random scalar polynomial with a specific number of terms.
    pub fn random(n_terms: usize, rng: &mut impl RngCore) -> Self {
        ScalarPoly((0..n_terms).map(|_| Scalar::random(rng)).collect())
    }

    /// Create a scalar polynomial where the first coefficient (the coefficient to x^0) is a
    /// specified secret and the remaining coefficients are random. `n_terms` is inclusive of the
    /// first coefficient so `n_terms == 1` means it will just return a polynomial where the single
    /// term is the passed in secret.
    pub fn random_using_secret(n_terms: usize, secret: Scalar, rng: &mut impl RngCore) -> Self {
        ScalarPoly(
            iter::once(secret)
                .chain((1..n_terms).map(|_| Scalar::random(rng)))
                .collect(),
        )
    }

    /// The number of terms in the polynomial. In FROST this corresponds to the threshold `t`.
    pub fn n_terms(&self) -> usize {
        self.0.len()
    }

    /// The first coefficient in the polynomial (the coefficient to x^0)
    pub fn first_coef(&self) -> &Scalar {
        &self.0[0]
    }

    /// Create a new scalar polynomial from a vector of scalars.
    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }
}

/// A participant's public commitment polynomial.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct PointPoly<Z = NonZero>(
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            deserialize = "Point<Normal, Public, Z>: serde::Deserialize<'de>",
            serialize = "Point<Normal, Public, Z>: serde::Serialize"
        ))
    )]
    pub Vec<Point<Normal, Public, Z>>,
);

impl<Z> PointPoly<Z> {
    /// Evaluate the point polynomial at position x.
    pub fn eval(&self, x: Scalar<Public, impl ZeroChoice>) -> Point<NonNormal, Public, Zero> {
        let xpows = iter::successors(Some(s!(1).public().mark_zero()), |xpow| {
            Some(s!(x * xpow).public().mark_zero())
        })
        .take(self.0.len())
        .collect::<Vec<_>>();
        crate::fun::op::lincomb(&xpows, &self.0)
    }

    /// Combine a vector of point polynomials into a joint polynomial.
    fn combine(mut polys: impl Iterator<Item = Self>) -> PointPoly<Zero> {
        // take the first point polynomial and collect its coefficients
        let mut combined_poly = polys
            .next()
            .expect("cannot combine empty list of polys")
            .0
            .into_iter()
            .map(|p| p.non_normal().mark_zero())
            .collect::<Vec<_>>();
        // add the coefficients of the remaining polys
        for poly in polys {
            for (combined_point, point) in combined_poly.iter_mut().zip(poly.0) {
                *combined_point = g!({ *combined_point } + point);
            }
        }
        PointPoly(combined_poly.into_iter().map(|p| p.normalize()).collect())
    }

    /// The number of terms in the polynomial. In FROST this corresponds to the threshold `t`.
    pub fn n_terms(&self) -> usize {
        self.0.len()
    }

    /// The first coefficient in the polynomial (the coefficient to x^0)
    pub fn first_coef(&self) -> Point<Normal, Public, Z> {
        self.0[0]
    }

    /// Fetch the points for the polynomial
    pub fn points(&self) -> &[Point<Normal, Public, Z>] {
        &self.0
    }
}

/// A KeyGen (distributed key generation) session
///
/// Created using [`Frost::new_keygen`]
///
/// [`Frost::new_keygen`]
#[derive(Clone, Debug)]
pub struct KeyGen {
    point_polys: Vec<PointPoly>,
    keygen_id: [u8; 32],
    frost_key: FrostKey,
}

impl KeyGen {
    /// Return the number of parties in the KeyGen
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

/// First round keygen errors
#[derive(Debug, Clone)]
pub enum NewKeyGenError {
    /// Received polynomial is of differing length.
    PolyDifferentLength(usize),
    /// Number of parties is less than the length of polynomials specifying the threshold.
    NotEnoughParties,
    /// Frost key is zero. Computationally unreachable, likely has been maliciously chosen.
    ZeroFrostKey,
    /// Verification share is zero. Computationally unreachable, likely has been maliciously chosen.
    ZeroVerificationShare,
}

impl core::fmt::Display for NewKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use NewKeyGenError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroFrostKey => write!(f, "The frost public key was zero. Computationally unreachable, one party is acting maliciously."),
            ZeroVerificationShare => write!(f, "Zero verification share. Computationally unreachable, one party is acting maliciously."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewKeyGenError {}

/// Second round KeyGen errors
#[derive(Debug, Clone)]
pub enum FinishKeyGenError {
    /// Secret share does not match the expected. Incorrect ordering?
    InvalidShare(usize),
    /// Proof of possession does not match the expected. Incorrect ordering?
    InvalidProofOfPossession(usize),
}

impl core::fmt::Display for FinishKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use FinishKeyGenError::*;
        match self {
            InvalidShare(i) => write!(
                f,
                "the secret share at index {} does not match the expected evaluation \
                of their point polynomial at our index. Check that the order and our index is correct",
                i
            ),
            &InvalidProofOfPossession(i) => write!(
                f,
                "the proof of possession provided by party at index {} was invalid, check ordering.",
                i
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinishKeyGenError {}

/// A joint FROST key
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct FrostKey {
    /// The joint public key of the frost multisignature.
    public_key: Point<Normal>,
    /// Everyone else's point polynomial evaluated at your index, used in partial signature validation.
    verification_shares: Vec<Point>,
    /// Number of partial signatures required to create a combined signature under this key.
    threshold: usize,
    /// The tweak applied to this frost key, tracks the aggregate tweak.
    tweak: Scalar<Public, Zero>,
}

impl FrostKey {
    /// The joint public key of the frost multisignature
    ///
    /// ## Return value
    ///
    /// A point
    pub fn public_key(&self) -> Point<Normal> {
        self.public_key
    }

    /// An iterator over the verification shares of each party in the key.
    ///
    /// ## Return value
    ///
    /// An iterator over verification share points
    pub fn verification_shares(&self) -> impl Iterator<Item = Point> + '_ {
        self.verification_shares.iter().map(|point| *point)
    }

    /// Apply a plain tweak to the frost public key.
    /// This is how you derive child public keys from a frost public key using BIP32.
    ///
    /// Tweak the frost public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G`. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let public_key = g!(self.public_key + tweak * G).normalize().non_zero()?;
        let tweak = s!(self.tweak + tweak).public();

        Some(FrostKey {
            public_key,
            verification_shares: self.verification_shares.clone(),
            threshold: self.threshold.clone(),
            tweak,
        })
    }

    /// Convert the key into a `Bip340AggKey`.
    ///
    /// This is the BIP340 compatible version of the key which you can put in a segwitv1
    pub fn into_xonly_key(self) -> XOnlyFrostKey {
        let (public_key, needs_negation) = self.public_key.into_point_with_even_y();
        let mut tweak = self.tweak;
        tweak.conditional_negate(needs_negation);
        XOnlyFrostKey {
            public_key,
            verification_shares: self.verification_shares,
            threshold: self.threshold,
            tweak,
            needs_negation,
        }
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The total number of signers in this frost multisignature.
    pub fn n_signers(&self) -> usize {
        self.verification_shares.len()
    }
}

/// A [`FrostKey`] that has been converted into an [`XOnlyFrostKey`] key.
///
/// This is the BIP340 compatible version of the key which you can put in a segwitv1 output and create BIP340 signatures under.
/// Tweaks applied to a `XOnlyFrostKey` are XOnly tweaks to the frost public key.
/// BIP340: <https://bips.xyz/340>
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct XOnlyFrostKey {
    /// The BIP340 public key of the frost multisignature.
    public_key: Point<EvenY>,
    /// Everyone else's point polynomial evaluated at your index, used in partial signature validation.
    verification_shares: Vec<Point>,
    /// Number of partial signatures required to create a combined signature under this key.
    threshold: usize,
    /// The tweak applied to this frost key, tracks the aggregate tweak.
    tweak: Scalar<Public, Zero>,
    /// Whether the secret keys need to be negated during
    needs_negation: bool,
}

impl XOnlyFrostKey {
    /// The joint public key of the frost multisignature
    ///
    /// ## Return value
    ///
    /// A point (normalized to have an even Y coordinate).
    pub fn public_key(&self) -> Point<EvenY> {
        self.public_key
    }

    /// An iterator over the verification shares of each party in the key.
    ///
    /// ## Return value
    ///
    /// An iterator over verification share points
    pub fn verification_shares(&self) -> impl Iterator<Item = Point> + '_ {
        self.verification_shares.iter().map(|point| *point)
    }

    /// Applies an "XOnly" tweak to the FROST public key.
    /// This is how you embed a taproot commitment into a frost public key
    ///
    /// Tweak the frost public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G` as an [`EvenY`] point. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let (new_public_key, needs_negation) = g!(self.public_key + tweak * G)
            .normalize()
            .non_zero()?
            .into_point_with_even_y();
        let mut new_tweak = s!(self.tweak + tweak).public();
        new_tweak.conditional_negate(needs_negation);
        let needs_negation = self.needs_negation ^ needs_negation;

        Some(Self {
            needs_negation,
            tweak: new_tweak,
            public_key: new_public_key,
            verification_shares: self.verification_shares,
            threshold: self.threshold,
        })
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The total number of signers in this frost multisignature.
    pub fn n_signers(&self) -> usize {
        self.verification_shares.len()
    }
}

#[derive(Clone, Debug)]
pub struct IssuanceShareFragment(Vec<u8>);

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> Frost<H, NG> {
    /// Create a scalar polynomial where the first coefficient is a specified secret
    /// and the remaining coefficients are generated using the internal nonce_gen.
    ///
    /// Depending on your choice of [`NonceGen`], this can be deterministic based
    /// on the secret and session_id. Be careful not to reuse scalar polys!
    ///
    /// ## Return value
    ///
    /// Returns a scalar polynomial
    pub fn new_scalar_poly(
        &self,
        secret: Scalar,
        threshold: usize,
        session_id: &[u8],
    ) -> ScalarPoly {
        let mut coeffs = vec![secret.clone()];
        for _ in 1..threshold {
            let schnorr = self.schnorr.nonce_gen();
            let nonce = derive_nonce!(
                nonce_gen => schnorr,
                secret => secret,
                public => [session_id]
            );
            coeffs.push(nonce)
        }
        ScalarPoly(coeffs)
    }

    /// Create our secret shares and proof-of-possession to be shared with other participants.
    ///
    /// Secret shares are created for every other participant by evaluating our secret polynomial
    /// at their participant index. f(i) for 1<=i<=n.
    ///
    /// Each secret share f(i) needs to be securely communicated to participant i. Additionally
    /// we share a proof of possession for the first coefficient in our secret scalar polynomial.
    ///
    /// ## Return value
    ///
    /// Returns a vector of secret shares and a proof-of-possession Signature
    /// The secret shares at index 0 is destined for participant 1.
    pub fn create_shares(
        &self,
        keygen: &KeyGen,
        scalar_poly: ScalarPoly,
    ) -> (Vec<Scalar<Secret, Zero>>, Signature) {
        let key_pair = self.schnorr.new_keypair(scalar_poly.0[0].clone());
        let pop = self
            .schnorr
            .sign(&key_pair, Message::<Public>::raw(&keygen.keygen_id));

        let shares = (1..=keygen.point_polys.len())
            .map(|i| scalar_poly.eval((i as u32).into()))
            .collect();

        (shares, pop)
    }

    pub fn create_issuance_fragments(
        &self,
        key_gen: &KeyGen,
        scalar_poly: ScalarPoly,
        num_issuance_shares: usize,
    ) -> Vec<Vec<IssuanceShareFragment>> {
        let issuance_shares: Vec<_> = (key_gen.point_polys.len()
            ..key_gen.point_polys.len() + num_issuance_shares)
            .map(|i| {
                scalar_poly.eval(Scalar::from_non_zero_u32(
                    NonZeroU32::new((i + 1) as u32).unwrap(),
                ))
            })
            .collect();

        // Get num_issuance_shares sets of N fragments for each share

        let fragments: Vec<_> = issuance_shares
            .iter()
            .map(|share| {
                let bytes: Vec<_> = [vec![0; 32].as_slice(), share.to_bytes().as_slice()].concat();
                let ss = shamirsecretsharing::create_shares(
                    &bytes,
                    key_gen.point_polys.len() as u8,
                    key_gen.frost_key.threshold as u8,
                )
                .unwrap();
                ss
            })
            .collect();

        let fragments_for_party: Vec<_> = (0..key_gen.point_polys.len())
            .map(|party_index| {
                fragments
                    .iter()
                    .map(|fragment_set| IssuanceShareFragment(fragment_set[party_index].clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        fragments_for_party
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG> Frost<H, NG> {
    /// Verify a proof of possession of a point
    ///
    /// ## Return value
    ///
    /// Returns `bool` true if the proof of possession matches the point
    fn verify_pop(&self, keygen: &KeyGen, point: Point, pop: Signature) -> bool {
        let (even_poly_point, _) = point.into_point_with_even_y();

        self.schnorr.verify(
            &even_poly_point,
            Message::<Public>::raw(&keygen.keygen_id),
            &pop,
        )
    }

    /// Collect all the public polynomials into a [`KeyGen`] session with a [`FrostKey`].
    ///
    /// Takes a vector of point polynomials to use for this [`FrostKey`].
    /// Also prepares a vector of verification shares for later.
    ///
    /// ## Return value
    ///
    /// Returns a [`KeyGen`] containing a [`FrostKey`]
    pub fn new_keygen(&self, point_polys: Vec<PointPoly>) -> Result<KeyGen, NewKeyGenError> {
        let len_first_poly = point_polys[0].n_terms();
        {
            if let Some((i, _)) = point_polys
                .iter()
                .enumerate()
                .find(|(_, point_poly)| point_poly.n_terms() != len_first_poly)
            {
                return Err(NewKeyGenError::PolyDifferentLength(i));
            }

            // Number of parties is less than the length of polynomials specifying the threshold
            if point_polys.len() < len_first_poly {
                return Err(NewKeyGenError::NotEnoughParties);
            }
        }

        let joint_poly = PointPoly::combine(point_polys.clone().into_iter());
        let public_key = joint_poly.0[0]
            .non_zero()
            .ok_or(NewKeyGenError::ZeroFrostKey)?;

        let mut keygen_hash = self.keygen_id_hash.clone();
        keygen_hash.update((len_first_poly as u32).to_be_bytes());
        keygen_hash.update((point_polys.len() as u32).to_be_bytes());
        for poly in &point_polys {
            for point in poly.0.iter() {
                keygen_hash.update(point.to_bytes());
            }
        }
        let keygen_id = keygen_hash.finalize().into();

        let verification_shares = (1..=point_polys.len())
            .map(|i| joint_poly.eval((i as u32).into()).normalize().non_zero())
            .collect::<Option<Vec<Point>>>()
            .ok_or(NewKeyGenError::ZeroVerificationShare)?;

        Ok(KeyGen {
            point_polys,
            keygen_id,
            frost_key: FrostKey {
                verification_shares,
                public_key,
                threshold: joint_poly.n_terms(),
                tweak: Scalar::zero().public(),
            },
        })
    }

    /// Collect the vector of all received secret shares into your total long-lived secret share.
    /// The secret_shares includes your own share as well as shares from each of the other parties.
    ///
    /// The secret_shares are validated to match the expected result
    /// by evaluating their polynomial at our participant index.
    ///
    /// Each participant's proof of possession is verified against their polynomial.
    ///
    /// # Return value
    ///
    /// Your total secret share Scalar and the [`FrostKey`]
    pub fn finish_keygen(
        &self,
        keygen: KeyGen,
        my_index: usize,
        secret_shares: Vec<Scalar<Secret, Zero>>,
        proofs_of_possession: Vec<Signature>,
    ) -> Result<(Scalar, FrostKey), FinishKeyGenError> {
        assert_eq!(
            secret_shares.len(),
            keygen.frost_key.verification_shares.len()
        );
        assert_eq!(secret_shares.len(), proofs_of_possession.len());

        for (i, (poly, pop)) in keygen
            .point_polys
            .iter()
            .zip(proofs_of_possession)
            .enumerate()
        {
            if !self.verify_pop(&keygen, poly.first_coef(), pop) {
                return Err(FinishKeyGenError::InvalidProofOfPossession(i));
            }
        }

        let mut total_secret_share = s!(0);
        for (i, (secret_share, poly)) in secret_shares.iter().zip(&keygen.point_polys).enumerate() {
            let expected_public_share = poly.eval(((my_index + 1) as u32).into());
            if g!(secret_share * G) != expected_public_share {
                return Err(FinishKeyGenError::InvalidShare(i));
            }
            total_secret_share += secret_share;
        }

        let total_secret_share = total_secret_share.non_zero().expect(
            "since verification shares are non-zero, the total secret share cannot be zero",
        );

        Ok((total_secret_share, keygen.frost_key))
    }

    /// Calls [`Frost::finish_keygen`] but immediately provides the the key as an [`XOnlyFrostKey`].
    ///
    /// # Return value
    ///
    /// Your total secret share Scalar and the [`XOnlyFrostKey`]
    pub fn finish_keygen_to_xonly(
        &self,
        keygen: KeyGen,
        my_index: usize,
        secret_shares: Vec<Scalar<Secret, Zero>>,
        proofs_of_possession: Vec<Signature>,
    ) -> Result<(Scalar, XOnlyFrostKey), FinishKeyGenError> {
        let (secret_share, frost_key) =
            self.finish_keygen(keygen, my_index, secret_shares, proofs_of_possession)?;
        Ok((secret_share, frost_key.into_xonly_key()))
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> Frost<H, NG> {
    /// Generate nonces for secret shares
    ///
    /// This method should be used carefully.
    /// This calls [`NonceKeyPair::generate`] internally with the frost instance's [`NonceGen`].
    /// See documentation for that for more usage info.
    ///
    /// When choosing a `secret` to use, if you are generating nonces prior to [`KeyGen`] completion,
    /// use the static first coefficient of your polynomial.
    /// Otherwise you can use your secret share of the frost key.
    ///
    /// The application must decide upon a unique `sid` for this frost multisignature.
    /// For example, the concatenation of: my_signing_index, verification_shares, purpose
    ///
    /// ## Return Value
    ///
    /// A NonceKeyPair comprised of secret scalars [r1, r2] and public nonces [R1, R2]
    /// [`NonceKeyPair::generate`]: crate::binonce::NonceKeyPair::generate
    pub fn gen_nonce(
        &self,
        secret: &Scalar,
        session_id: &[u8],
        public_key: Option<Point>,
        message: Option<Message<'_>>,
    ) -> NonceKeyPair {
        NonceKeyPair::generate(
            self.schnorr.nonce_gen(),
            secret,
            session_id,
            public_key,
            message,
        )
    }
}

/// A FROST signing session
///
/// Created using [`Frost::start_sign_session`].
///
/// [`Frost::start_sign_session`]
#[derive(Clone, Debug, PartialEq)]
pub struct SignSession {
    binding_coeff: Scalar,
    nonces_need_negation: bool,
    agg_nonce: Point<EvenY>,
    challenge: Scalar<Public, Zero>,
    nonces: BTreeMap<usize, Nonce>,
}

impl SignSession {
    /// Fetch the participant indices for this signing session.
    ///
    /// ## Return value
    ///
    /// An iterator of participant indices
    pub fn participants(&self) -> impl DoubleEndedIterator<Item = usize> + '_ {
        self.nonces.iter().map(|(i, _)| *i)
    }
}

/// Calculate the lagrange coefficient for participant with index x_j and other signers indexes x_ms
fn lagrange_lambda(x_j: u32, x_ms: &[u32]) -> Scalar {
    let x_j = Scalar::from(x_j)
        .non_zero()
        .expect("target xcoord can not be zero");
    x_ms.iter()
        .map(|x_m| {
            Scalar::from(*x_m)
                .non_zero()
                .expect("index can not be zero")
        })
        .fold(Scalar::one(), |acc, x_m| {
            let denominator = s!(x_m - x_j)
                .non_zero()
                .expect("removed duplicate indexes")
                .invert();
            s!(acc * x_m * denominator)
        })
}

impl<H: Digest<OutputSize = U32> + Clone, NG> Frost<H, NG> {
    /// Start a FROST signing session.
    ///
    /// Signing participants must use a common set of nonces to each produce a
    /// signature share. See [`Frost::gen_nonce`] and [`NonceKeyPair::generate`].
    ///
    /// ## Return value
    ///
    /// A FROST signing session
    pub fn start_sign_session(
        &self,
        frost_key: &XOnlyFrostKey,
        nonces: Vec<(usize, Nonce)>,
        message: Message,
    ) -> SignSession {
        let mut nonce_map: BTreeMap<_, _> =
            nonces.into_iter().map(|(i, nonce)| (i, nonce)).collect();

        let agg_nonce_jac: [Point<NonNormal, Public, Zero>; 2] =
            nonce_map
                .iter()
                .fold([Point::zero().non_normal(); 2], |acc, (_, nonce)| {
                    [
                        g!({ acc[0] } + { nonce.0[0] }),
                        g!({ acc[1] } + { nonce.0[1] }),
                    ]
                });
        let agg_nonce_points = [
            agg_nonce_jac[0].normalize().non_zero().unwrap_or_else(|| {
                // Like in musig spec, if the final nonce is zero we set to the generator
                G.clone().normalize()
            }),
            agg_nonce_jac[1]
                .normalize()
                .non_zero()
                .unwrap_or_else(|| G.clone().normalize()),
        ];

        let binding_coeff = Scalar::from_hash(
            self.binding_hash
                .clone()
                .add(agg_nonce_points[0])
                .add(agg_nonce_points[1])
                .add(frost_key.public_key())
                .add(message),
        );
        let (agg_nonce, nonces_need_negation) =
            g!({ agg_nonce_points[0] } + binding_coeff * { agg_nonce_points[1] })
                .normalize()
                .non_zero()
                .expect("computationally unreachable, input is a hash")
                .into_point_with_even_y();

        for (_, nonce) in &mut nonce_map {
            nonce.conditional_negate(nonces_need_negation);
        }

        let challenge = self
            .schnorr
            .challenge(&agg_nonce, &frost_key.public_key(), message);

        SignSession {
            binding_coeff,
            nonces_need_negation,
            agg_nonce,
            challenge,
            nonces: nonce_map,
        }
    }

    /// Generates a partial signature share under the frost key using a secret share.
    ///
    /// ## Return value
    ///
    /// Returns a signature Scalar.
    pub fn sign(
        &self,
        frost_key: &XOnlyFrostKey,
        session: &SignSession,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonce: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        let mut lambda = lagrange_lambda(
            my_index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != my_index)
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let [mut r1, mut r2] = secret_nonce.secret;
        r1.conditional_negate(session.nonces_need_negation);
        r2.conditional_negate(session.nonces_need_negation);

        let b = &session.binding_coeff;
        let x = secret_share;
        let c = &session.challenge;
        s!(r1 + (r2 * b) + lambda * x * c).public()
    }

    /// Verify a partial signature for a participant at `index` (from zero).
    ///
    /// Check partial signature against the verification shares created during keygen.
    ///
    /// ## Return Value
    ///
    /// Returns `bool`, true if partial signature is valid.
    pub fn verify_signature_share(
        &self,
        frost_key: &XOnlyFrostKey,
        session: &SignSession,
        index: usize,
        signature_share: Scalar<Public, Zero>,
    ) -> bool {
        let s = signature_share;
        let mut lambda = lagrange_lambda(
            index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != index)
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let c = &session.challenge;
        let b = &session.binding_coeff;
        let X = frost_key.verification_shares().nth(index).unwrap();
        let [ref R1, ref R2] = session
            .nonces
            .get(&index)
            .expect("verifying party index that is not part of frost signing coalition")
            .0;
        g!(R1 + b * R2 + (c * lambda) * X - s * G).is_zero()
    }

    /// Combine a vector of partial signatures into an aggregate signature.
    ///
    /// Includes the [`XOnlyFrostKey`] tweak in the combined signature.
    ///
    /// ## Return value
    ///
    /// Returns a combined schnorr [`Signature`] for the message.
    /// Valid against the frost public key.
    pub fn combine_signature_shares(
        &self,
        frost_key: &XOnlyFrostKey,
        session: &SignSession,
        partial_sigs: Vec<Scalar<Public, Zero>>,
    ) -> Signature {
        let ck = s!(session.challenge * frost_key.tweak);
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, partial_sig| s!(acc + partial_sig).public())
            .unwrap_or(Scalar::zero().public());
        Signature {
            R: session.agg_nonce,
            s: s!(sum_s + ck).public(),
        }
    }
}

/// Constructor for a Frost instance using deterministic nonce generation.
///
/// If you use deterministic nonce generation you will have to provide a unique session id to every signing session.
/// The advantage is that you will be able to regenerate the same nonces at a later point from [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_deterministic_nonces<H: Tagged + Digest<OutputSize = U32>>(
) -> Frost<H, nonce::Deterministic<H>> {
    Frost::default()
}

/// Constructor for a Frost instance using synthetic nonce generation.
///
/// Synthetic nonce generation mixes in external randomness into nonce generation which means you
/// don't need a unique session id for each signing session to guarantee security. The disadvantage
/// is that you may have to store and recall somehow the nonces generated from
/// [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_synthetic_nonces<H, R>() -> Frost<H, nonce::Synthetic<H, nonce::GlobalRng<R>>>
where
    H: Tagged + Digest<OutputSize = U32>,
    R: RngCore + Default,
{
    Frost::default()
}

/// Create a Frost instance which does not handle nonce generation.
///
/// You can still sign with this instance but you you will have to generate nonces in your own way.
pub fn new_without_nonce_generation<H>() -> Frost<H, ()>
where
    H: Tagged + Digest<OutputSize = U32>,
{
    Frost::default()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::seq::SliceRandom;
    use secp256kfun::{
        nonce::Deterministic,
        proptest::{
            arbitrary::any,
            option, proptest,
            strategy::{Just, Strategy},
            test_runner::{RngAlgorithm, TestRng},
        },
    };
    use sha2::Sha256;

    #[test]
    fn frost_test_issuance() {
        // Create a secret polynomial for each participant
        let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
        let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
        let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);

        let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
            Deterministic::<Sha256>::default(),
        ));
        let point_polys = vec![
            sp1.to_point_poly(),
            sp2.to_point_poly(),
            sp3.to_point_poly(),
        ];

        let KeyGen = frost.new_keygen(point_polys).unwrap();
        let (shares1, pop1) = frost.create_shares(&KeyGen, sp1.clone());
        let (shares2, pop2) = frost.create_shares(&KeyGen, sp2.clone());
        let (shares3, pop3) = frost.create_shares(&KeyGen, sp3.clone());

        let fragments1 = frost.create_issuance_fragments(&KeyGen, sp1, 1);
        let fragments2 = frost.create_issuance_fragments(&KeyGen, sp2, 1);
        let fragments3 = frost.create_issuance_fragments(&KeyGen, sp3, 1);

        // Participants share their fragments.
        let p1_recieved_fragments = vec![fragments2[0][0].clone(), fragments3[0][0].clone()];
        let p2_recieved_fragments = vec![fragments1[1][0].clone(), fragments3[1][0].clone()];
        let _p3_recieved_fragments = vec![fragments1[2][0].clone(), fragments2[2][0].clone()];

        // Now we can issue a new keygen with 2 sets of fragments
        // Since this is the first new issuance, we use the first set of fragments that each party recieved

        // A new party recieves fragments from a threshold number of parties:
        let p4_collected_fragments = vec![
            vec![fragments1[0][0].clone(), fragments1[1][0].clone()], // From P1 and P2
            vec![fragments2[0][0].clone(), fragments2[1][0].clone()], // From P1 and P2
            vec![fragments3[0][0].clone(), fragments3[1][0].clone()], // From P1 and P2
        ];

        let p4_collected_fragments_vec: Vec<Vec<Vec<u8>>> = p4_collected_fragments
            .iter()
            .map(|shares| shares.iter().map(|share| share.0.clone()).collect())
            .collect();

        let mut restored_shares = vec![];
        for fragments in p4_collected_fragments_vec {
            // let fragments = vec![
            //     p4_collected_fragments[0][i].0.clone(),
            //     p4_collected_fragments[1][i].0.clone(),
            // ];

            let r: [u8; 64] = shamirsecretsharing::combine_shares(&fragments)
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap();

            let mut scalar_bytes: [u8; 32] = Default::default();
            scalar_bytes.copy_from_slice(&r[32..]);

            let scalar_share = Scalar::from_bytes(scalar_bytes).unwrap();
            restored_shares.push(scalar_share);
        }

        // ALSO NEED TO SHAMIR SHARE POPS?
        let proofs_of_possession = vec![pop1, pop2, pop3];

        // LOAD p4
        let (secret_share4, frost_key4) = frost
            .finish_keygen(
                KeyGen.clone(),
                3,
                restored_shares.clone(),
                proofs_of_possession.clone(),
            )
            .unwrap();

        let (secret_share1, frost_key) = frost
            .finish_keygen(
                KeyGen.clone(),
                0,
                vec![shares1[0].clone(), shares2[0].clone(), shares3[0].clone()],
                proofs_of_possession.clone(),
            )
            .unwrap();
        let (_secret_share2, frost_key2) = frost
            .finish_keygen(
                KeyGen.clone(),
                1,
                vec![shares1[1].clone(), shares2[1].clone(), shares3[1].clone()],
                proofs_of_possession.clone(),
            )
            .unwrap();
        let (secret_share3, frost_key3) = frost
            .finish_keygen(
                KeyGen.clone(),
                2,
                vec![shares1[2].clone(), shares2[2].clone(), shares3[2].clone()],
                proofs_of_possession,
            )
            .unwrap();

        assert_eq!(frost_key, frost_key2);
        assert_eq!(frost_key, frost_key3);

        let xonly_frost_key = frost_key.into_xonly_key();
        let xonly_frost_key2 = frost_key2.into_xonly_key();
        let xonly_frost_key3 = frost_key3.into_xonly_key();

        let verification_shares_bytes: Vec<_> = xonly_frost_key
            .verification_shares
            .iter()
            .map(|share| share.to_bytes())
            .collect();

        // Create unique session IDs for these signing sessions
        let sid1 = [
            verification_shares_bytes.concat().as_slice(),
            b"frost-end-to-end-test-1".as_slice(),
            b"0".as_slice(),
        ]
        .concat();

        let sid2 = [
            verification_shares_bytes.concat().as_slice(),
            b"frost-end-to-end-test-2".as_slice(),
            b"2".as_slice(),
        ]
        .concat();

        let message = Message::plain("test", b"test");
        let nonce1 = frost.gen_nonce(
            &secret_share1,
            &sid1,
            Some(xonly_frost_key.public_key().normalize()),
            Some(message),
        );
        let nonce3 = frost.gen_nonce(
            &secret_share3,
            &sid2,
            Some(xonly_frost_key.public_key().normalize()),
            Some(message),
        );
        let nonces = vec![(0, nonce1.public()), (2, nonce3.public())];
        let nonces2 = vec![(0, nonce1.public()), (2, nonce3.public())];

        let session = frost.start_sign_session(&xonly_frost_key, nonces, message);
        dbg!(&session);
        {
            let session2 = frost.start_sign_session(&xonly_frost_key2, nonces2, message);
            assert_eq!(session2, session);
        }

        let sig1 = frost.sign(&xonly_frost_key, &session, 0, &secret_share1, nonce1);
        let sig3 = frost.sign(&xonly_frost_key3, &session, 2, &secret_share3, nonce3);

        dbg!(sig1, sig3);

        assert!(frost.verify_signature_share(&xonly_frost_key, &session, 0, sig1));
        assert!(frost.verify_signature_share(&xonly_frost_key, &session, 2, sig3));
        let combined_sig =
            frost.combine_signature_shares(&xonly_frost_key, &session, vec![sig1, sig3]);

        assert!(frost.schnorr.verify(
            &xonly_frost_key.public_key(),
            Message::<Public>::plain("test", b"test"),
            &combined_sig
        ));
    }

    proptest! {
        #[test]
        fn frost_prop_test(
            (n_parties, threshold) in (2usize..=4).prop_flat_map(|n| (Just(n), 2usize..=n)),
            plain_tweak in option::of(any::<Scalar<Public, Zero>>()),
            xonly_tweak in option::of(any::<Scalar<Public, Zero>>())
        ) {
            let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
                Deterministic::<Sha256>::default(),
            ));
            assert!(threshold <= n_parties);

            // create some scalar polynomial for each party
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
            let scalar_polys = (0..n_parties).map(|_| ScalarPoly::random(threshold, &mut rng)).collect::<Vec<_>>();
            let point_polys = scalar_polys.iter().map(ScalarPoly::to_point_poly).collect::<Vec<_>>();
            let keygen = frost.new_keygen(point_polys).unwrap();
            let (shares, proofs_of_possesion): (Vec<_>, Vec<_>) =  scalar_polys.into_iter().map(|sp| frost.create_shares(&keygen, sp)).unzip();
            // collect the received shares for each party
            let received_shares = (0..n_parties).map(|party_index| (0..n_parties).map(|share_index| shares[share_index][party_index].clone()).collect()).collect::<Vec<Vec<_>>>();

            // finish keygen for each party
            let (secret_shares, frost_keys): (Vec<_>, Vec<_>) = (0..n_parties).map(|party_index| {
                let (secret_share, mut frost_key) = frost.finish_keygen(
                    keygen.clone(),
                    party_index,
                    received_shares[party_index].clone(),
                    proofs_of_possesion.clone(),
                )
                .unwrap();

                if let Some(tweak) = plain_tweak {
                    frost_key = frost_key.tweak(tweak).unwrap();
                }

                let mut xonly_frost_key = frost_key.into_xonly_key();

                if let Some(tweak) = xonly_tweak {
                    xonly_frost_key = xonly_frost_key.tweak(tweak).unwrap();
                }
                (secret_share, xonly_frost_key)
            }).unzip();

            // use a boolean mask for which t participants are signers
            let mut signer_mask = vec![true; threshold];
            signer_mask.append(&mut vec![false; n_parties - threshold]);
            // shuffle the mask for random signers
            signer_mask.shuffle(&mut rng);

            let signer_indexes: Vec<_> = signer_mask
                .iter()
                .enumerate()
                .filter(|(_, is_signer)| **is_signer)
                .map(|(i,_)| i)
                .collect();

            let verification_shares_bytes: Vec<_> = frost_keys[signer_indexes[0]]
                .verification_shares
                .iter()
                .map(|share| share.to_bytes())
                .collect();

            let sid = [
                frost_keys[signer_indexes[0]].public_key().to_xonly_bytes().as_slice(),
                verification_shares_bytes.concat().as_slice(),
                b"frost-prop-test".as_slice(),
            ]
            .concat();
            let nonces: Vec<NonceKeyPair> = signer_indexes.iter().map(|i|
                frost.gen_nonce(
                    &secret_shares[*i],
                    &[sid.as_slice(), [*i as u8].as_slice()].concat(),
                    Some(frost_keys[signer_indexes[0]].public_key().normalize()),
                    None)
                ).collect();

            let mut received_nonces: Vec<_> = vec![];
            for (i, nonce) in signer_indexes.iter().zip(nonces.clone()) {
                received_nonces.push((*i, nonce.public()));
            }

            let message = Message::plain("test", b"test");
            let signing_session = frost.start_sign_session(
                &frost_keys[signer_indexes[0]],
                received_nonces.clone(),
                message
            );

            let mut signatures = vec![];
            for i in 0..signer_indexes.len() {
                let signer_index = signer_indexes[i];
                let session = frost.start_sign_session(
                    &frost_keys[signer_index],
                    received_nonces.clone(),
                    message
                );
                let sig = frost.sign(
                    &frost_keys[signer_index],
                    &session, signer_index,
                    &secret_shares[signer_index],
                    nonces[i].clone()
                );
                assert!(frost.verify_signature_share(
                    &frost_keys[signer_index],
                    &session,
                    signer_index,
                    sig)
                );
                signatures.push(sig);
            }
            let combined_sig = frost.combine_signature_shares(
                &frost_keys[signer_indexes[0]],
                &signing_session,
                signatures);

            assert!(frost.schnorr.verify(
                &frost_keys[signer_indexes[0]].public_key(),
                message,
                &combined_sig
            ));
        }
    }

    #[test]
    fn test_lagrange_lambda() {
        let res = s!((1 * 4 * 5) * {
            s!((1 - 2) * (4 - 2) * (5 - 2))
                .non_zero()
                .expect("")
                .invert()
        });
        assert_eq!(res, lagrange_lambda(2, &[1, 4, 5]));
    }
}
