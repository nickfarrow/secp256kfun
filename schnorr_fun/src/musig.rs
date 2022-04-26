//! The MuSig2 multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{musig::{MuSig, Party}, Schnorr, Message, nonce::Deterministic};
//! use sha2::Sha256;
//! // use sha256 with deterministic nonce generation
//! let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
//! // create a keylist
//! use schnorr_fun::fun::Scalar;
//! let kp1 = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! let public_key1 = kp1.public_key();
//! # let kp2 = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let public_key2 = kp2.public_key();
//! # let kp3 = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let public_key3 = kp3.public_key();
//! // recieve the public keys of all other participants to form the aggregate key.
//! let keylist = musig.new_keylist(vec![
//!     p1_public_key,
//!     p2_public_key,
//!     p3_public_key,
//! ]);
//! let agg_key = keylist.agg_public_key();
//!
//! // create unique nonce, and send public nonce to other parties
//! let p1_nonce = musig.gen_nonces(&keypair.sk, &keylist, b"session-id-1337");
//! let p1_public_nonce = p1_nonce.public;
//! # let p2_nonce = musig.gen_nonces(&keypair.sk, &keylist, b"session-id-1337");
//! # let p3_nonce = musig.gen_nonces(&keypair.sk, &keylist, b"session-id-1337");
//! let nonces = vec![p1_public_nonce, p2_public_nonce, p3_public_nonce];
//! // Once you've got the nonces from the other two (p2_nonce and p3_nonce) you can start the signing session.
//! let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! let mut session = musig.start_sign_session(&keylist, nonces, message).unwrap();
//! // sign with our (single) local keypair
//! let p1_sig = musig.sign(&keylist, 0, kp1.sk, p1_nonce, &session);
//! # let p2_sig = musig.sign(&keylist, 1, kp2.sk, p2_nonce, &session);
//! # let p3_sig = musig.sign(&keylist, 2, kp3.sk, p3_nonce, &session);
//! // receive p1_sig and p3_sig from somewhere and check they're valid
//! assert!(musig.verify_partial_signature(&keylist, &session, 1, p2_sig));
//! assert!(musig.verify_partial_signature(&keylist, &session, 2, p3_sig));
//! // combine them with ours into the final signature
//! let sig = musig.combine_partial_signatures(&keylist, &session, [p1_sig, p2_sig, p3_sig]);
//! // check it's a valid normal Schnorr signature
//! musig.schnorr.verify(&agg_key, message, &sig);
//! ```
//!
//! ## Description
//!
//! The MuSig2 multisignature scheme lets you aggregate multiple public keys into a single public
//! key that requires all of the corresponding secret keys to authorize a signature under the aggregate key.
//!
//! This implementation is protocol compatible with the implementation merged into
//! [secp256k1-zkp].
//!
//! See [the excellent paper] for the abstract details of the protocol.
//!
//! [the excellent paper]: https://eprint.iacr.org/2020/1261.pdf
//! [secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/131
use crate::{adaptor::EncryptedSignature, Message, Schnorr, Signature, Vec};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::NonceGen,
    s, Point, Scalar, XOnly, G,
};

/// The MuSig context.
pub struct MuSig<H, S = ()> {
    /// The hash used to compress the key list to 32 bytes.
    pub pk_hash: H,
    /// The hash used to generate each key's coefficient.
    pub coeff_hash: H,
    /// The hash used to generate the nonce coefficients.
    pub nonce_coeff_hash: H,
    /// The instance of the underlying Schnorr context.
    pub schnorr: S,
}

impl<H: Tagged, S> MuSig<H, S> {
    fn _new(schnorr: S) -> Self {
        Self {
            pk_hash: H::default().tagged(b"KeyAgg list"),
            coeff_hash: H::default().tagged(b"KeyAgg coefficient"),
            nonce_coeff_hash: H::default().tagged(b"MuSig/noncecoef"),
            schnorr,
        }
    }
}

impl<H: Tagged, S: Default> Default for MuSig<H, S> {
    fn default() -> Self {
        MuSig::_new(S::default())
    }
}

impl<H: Tagged, NG> MuSig<H, Schnorr<H, NG>> {
    /// Generate a new MuSig context from a Schnorr context.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self::_new(schnorr)
    }
}

/// A list of keys aggregated into a single key.
///
/// Created using [`MuSig::new_keylist`].
///
/// The `KeyList` can't be serialized but it's very efficient to re-create it from the initial list of keys.
///
/// [`MuSig::new_keylist`]
#[derive(Debug, Clone)]
pub struct KeyList {
    /// The parties involved in the key aggregation.
    parties: Vec<XOnly>,
    /// The coefficients of each key
    coefs: Vec<Scalar<Public>>,
    /// The aggregate key
    agg_key: Point<EvenY>,
    /// The tweak on the aggregate key
    tweak: Scalar<Public, Zero>,
    /// Whether this aggregate key needs negation.
    needs_negation: bool,
}

impl KeyList {
    /// The `XOnly` aggregated key for the keylist.
    pub fn agg_public_key(&self) -> XOnly {
        self.agg_key.to_xonly()
    }
    /// The aggregated key for the keylist as a `Point`.
    pub fn agg_verification_key(&self) -> Point<EvenY> {
        self.agg_key
    }
    /// An iterator over the **public keys** of each party in the keylist.
    pub fn keys(&self) -> impl Iterator<Item = XOnly> + '_ {
        self.parties.iter().map(|xonly| *xonly)
    }

    /// Tweak the aggregate MuSig public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G`. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// This is how you embed a taproot commitment into a key.
    ///
    /// Also updates whether the MuSig KeyList needs negation.
    /// XOR of existing MuSig KeyList needs_negation and new tweaked key needs_negation.
    /// If both need negation, they will cancel out.
    ///
    /// Public key
    ///     X = (b*x) * G
    /// where b = 1 or -1
    /// For a tweak t: X' = X + t * G.
    /// If X' needs negation then we need secret
    ///     -(b*x + t) = -b*x - t
    /// So new b = -b and t = -t.
    /// If X' doesn't need negation, leave b as is.
    /// i.e. previous needs_negation XOR new needs_negation.
    ///
    /// ## Return value
    ///
    /// Returns a new MuSig KeyList with the same parties but a different aggregated public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn tweak(&self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let new_tweak = s!(0 + tweak).mark::<Public>();
        let (agg_key, needs_negation) = g!(self.agg_key + new_tweak * G)
            .mark::<NonZero>()?
            .into_point_with_even_y();

        // Store accumulated tweak
        let mut tweak = s!(self.tweak + tweak).mark::<Public>();
        tweak.conditional_negate(needs_negation);

        let needs_negation = self.needs_negation ^ needs_negation;

        Some(KeyList {
            parties: self.parties.clone(),
            coefs: self.coefs.clone(),
            agg_key,
            tweak,
            needs_negation,
        })
    }
}

impl<H: Digest<OutputSize = U32> + Clone, S> MuSig<H, S> {
    /// Generates a new key list from a list of parties.
    ///
    /// Each party can be local (you know the secret key) or remote (you only know the public key).
    ///
    /// ## Example
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{Point, Scalar, XOnly},
    ///     musig::{MuSig, Party},
    ///     nonce::Deterministic,
    ///     Schnorr,
    /// };
    /// # let my_secret_key = Scalar::random(&mut rand::thread_rng());
    /// # let their_public_key = XOnly::random(&mut rand::thread_rng());
    /// use sha2::Sha256;
    /// let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    /// let my_keypair = musig.schnorr.new_keypair(my_secret_key);
    /// let my_public_key = my_keypair.public_key();
    /// // Note the keys have to come in the same order on the other side!
    /// let keylist = musig.new_keylist(vec![
    ///     their_public_key,
    ///     my_public_key,
    /// ]);
    /// ```
    pub fn new_keylist(&self, parties: Vec<XOnly>) -> KeyList {
        let keys = parties.clone();
        let coeff_hash = {
            let L = self.pk_hash.clone().add(&keys[..]).finalize();
            self.coeff_hash.clone().add(L.as_slice())
        };

        let mut second = None;
        let coefs = keys
            .iter()
            .map(|key| {
                // This is the logic for IsSecond from appendix B of the MuSig2 paper
                if second.is_none() && key != &keys[0] {
                    second = Some(key);
                }
                if second != Some(key) {
                    Scalar::from_hash(coeff_hash.clone().add(key))
                } else {
                    Scalar::one()
                }
                .mark::<Public>()
            })
            .collect::<Vec<_>>();
        let points = keys.into_iter().map(|x| x.to_point()).collect::<Vec<_>>();

        let (agg_key, needs_negation) = crate::fun::op::lincomb(coefs.iter(), points.iter())
            .expect_nonzero("computationally unreachable: linear combination of hash randomised points cannot add to zero")
            .into_point_with_even_y();

        KeyList {
            parties,
            coefs,
            agg_key,
            tweak: Scalar::zero().mark::<Public>(),
            needs_negation,
        }
    }
}

/// A nonce (pair of points) that each party must share with the others in the first stage of signing.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Nonce(pub [Point; 2]);

impl Nonce {
    /// Reads the pair of nonces from 66 bytes (two 33-byte serialized points).
    pub fn from_bytes(bytes: [u8; 66]) -> Option<Self> {
        let R1 = Point::from_slice(&bytes[..33])?;
        let R2 = Point::from_slice(&bytes[33..])?;
        Some(Nonce([R1, R2]))
    }

    /// Serializes a public nonce as  as 66 bytes (two 33-byte serialized points).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(self.0[0].to_bytes().as_ref());
        bytes[33..].copy_from_slice(self.0[1].to_bytes().as_ref());
        bytes
    }

    /// Negate the two nonces
    pub fn conditional_negate(&mut self, needs_negation: bool) {
        self.0[0] = self.0[0].conditional_negate(needs_negation);
        self.0[1] = self.0[1].conditional_negate(needs_negation);
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "MuSig2 public nonce pair",
    fn from_bytes(bytes: [u8;66]) -> Option<Nonce> {
        Nonce::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nonce: &Nonce) -> [u8;66] {
        nonce.to_bytes()
    }
}

/// A pair of secret nonces along with the public portion.
///
/// A nonce key pair can be created manually with [`from_secrets`] or with [`MuSig::gen_nonces`].
///
/// [`from_secrets`]: Self::from_secrets
/// [`MuSig::gen_nonces`]: MuSig::gen_nonces
#[derive(Debug, Clone, PartialEq)]
pub struct NonceKeyPair {
    /// The public nonce
    pub(crate) public: Nonce,
    /// The secret nonce
    pub(crate) secret: [Scalar; 2],
}

impl NonceKeyPair {
    /// Creates a keypair from two secret scalars.
    ///
    /// ## Security
    ///
    /// You must never use the same `NonceKeyPair` into two signing sessions.
    ///
    /// ## Example
    /// ```
    /// use schnorr_fun::{fun::Scalar, musig::NonceKeyPair};
    /// let nkp = NonceKeyPair::from_secrets([
    ///     Scalar::random(&mut rand::thread_rng()),
    ///     Scalar::random(&mut rand::thread_rng()),
    /// ]);
    /// ```
    pub fn from_secrets(secret: [Scalar; 2]) -> Self {
        let [ref r1, ref r2] = secret;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret,
        }
    }
    /// Deserializes a nonce key pair from 64-bytes (two 32-byte serialized scalars).
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let r1 = Scalar::from_slice(&bytes[..32])?.mark::<NonZero>()?;
        let r2 = Scalar::from_slice(&bytes[32..])?.mark::<NonZero>()?;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        let pub_nonce = Nonce([R1, R2]);
        Some(NonceKeyPair {
            public: pub_nonce,
            secret: [r1, r2],
        })
    }

    /// Serializes a nonce key pair to 64-bytes (two 32-bytes serialized scalars).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.secret[0].to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.secret[1].to_bytes().as_ref());
        bytes
    }

    /// Get the secret portion of the nonce key pair (don't share this!)
    pub fn secret(&self) -> &[Scalar; 2] {
        &self.secret
    }

    /// Get the public portion of the nonce key pair (share this!)
    pub fn public(&self) -> Nonce {
        self.public
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "MuSig secret nonce pair",
    fn from_bytes(bytes: [u8;64]) -> Option<NonceKeyPair> {
        NonceKeyPair::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nkp: &NonceKeyPair) -> [u8;64] {
        nkp.to_bytes()
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> MuSig<H, Schnorr<H, NG>> {
    /// TODO
    /// Generate nonces for your local keys in keylist.
    ///
    /// It is very important to carefully consider the implications of your choice of underlying
    /// [`NonceGen`].
    ///
    /// Using a [`Synthetic`] nonce generator will mean you don't have to worry about passing a
    /// unique `sid` (session id) to this function for each signing session. The downside is that
    /// you must recall the result of `gen_nonces` somewhere and store it for use when you want to
    /// start the signing session with [`start_sign_session`].
    ///
    /// Using a [`Deterministic`] nonce generator means you **must** never start two signing
    /// sessions with nonces generated from the same `sid`. If you do your secret key will be
    /// recoverable from the two partial signatures you created with the same nonce. The upside is
    /// that you can call [`start_sign_session_deterministic`] with the `sid` you originally passed
    /// to `gen_nonces` without having to store the output of `gen_nonces`.
    ///
    /// Note that the API allows you to BYO nonces by creating `NonceKeyPair`s manually.
    ///
    /// [`NonceGen`]: secp256kfun::nonce::NonceGen
    /// [`Synthetic`]: secp256kfun::nonce::Synthetic
    /// [`Deterministic`]: secp256kfun::nonce::Deterministic
    /// [`start_sign_session`]: Self::start_sign_session
    pub fn gen_nonces(&self, secret: &Scalar, keylist: &KeyList, sid: &[u8]) -> NonceKeyPair {
        let r1 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r1", keylist.agg_public_key(), sid]
        );
        let r2 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r2", keylist.agg_public_key(), sid]
        );
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }
    }
}

/// Marker type for indicating the [`SignSession`] is being used to create an ordinary Schnorr
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct Ordinary;

/// Marks the [`SignSession`] as being used to create an adaptor (a.k.a. one-time encrypted)
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct Adaptor {
    y_needs_negation: bool,
}

/// A signing session.
///
/// Created by [`start_sign_session`] or [`start_encrypted_sign_session`].
/// The type parameter records whether you are trying to jointly generate a signature or an adaptor signature.
///
/// ## Security
///
/// This struct has **secret nonces** in it up until you call [`clear_secrets`] or [`sign`]. If
/// a malicious party gains access to it before and you generate a partial signature with this session they
/// will be able to recover your secret key. If this is a concern simply avoid serializing this
/// struct (until you've cleared it) and recreate it only when you need it.
///
/// [`start_sign_session`]: MuSig::start_sign_session
/// [`start_encrypted_sign_session`]: MuSig::start_encrypted_sign_session
/// [`clear_secrets`]: SignSession::clear_secrets
/// [`sign_all`]: MuSig::sign_all
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct SignSession<T = Ordinary> {
    b: Scalar<Public, Zero>,
    c: Scalar<Public, Zero>,
    public_nonces: Vec<Nonce>,
    R: Point<EvenY>,
    nonce_needs_negation: bool,
    signing_type: T,
}

// impl<T> SignSession<T> {
//     /// Removes all secret nonce data from the session.
//     ///
//     /// The session works as normal except that it can no longer be used for signing ([`sign`] will return an empty vector).
//     ///
//     /// [`sign`]: MuSig::sign
//     pub fn clear_secrets(&mut self) {
//         self.local_secret_nonces.drain(..);
//     }
// }

impl<H: Digest<OutputSize = U32> + Clone, NG> MuSig<H, Schnorr<H, NG>> {
    /// Start a signing session.
    ///
    /// You must provide the public nonces for this signing session in the correct order.
    ///
    /// ## Return Value
    ///
    /// Returns `None` in the case that the `remote_nonces` have been (maliciously) selected to
    /// cancel out your local nonces.
    /// This is not a security issue -- we just can't continue the protocol if this happens.
    ///
    /// # Panics
    ///
    /// Panics if number of nonces does not align with the parties in `keylist`.
    pub fn start_sign_session(
        &self,
        keylist: &KeyList,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
    ) -> Option<SignSession> {
        let (b, c, public_nonces, R, nonce_needs_negation) =
            self._start_sign_session(keylist, nonces, message, &Point::zero())?;
        Some(SignSession {
            b,
            c,
            public_nonces,
            R,
            nonce_needs_negation,
            signing_type: Ordinary,
        })
    }

    /// Start an encrypted signing session.
    ///
    /// i.e. a session to produce an adaptor signature under `encryption_key`.
    /// See [`adaptor`] for a more general description of adaptor signatures.
    ///
    /// You must provide you local secret nonces (the public portion must be shared with the other
    /// signer(s)). If you are using deterministic nonce generation it's possible to use
    /// [`start_encrypted_sign_session_deterministic`] instead.
    ///
    /// ## Return Value
    ///
    /// Returns `None` in the case that the `remote_nonces` have been (maliciously) selected to
    /// cancel out your local nonces.
    /// This is not a security issue -- we just can't continue the protocol if this happens.
    ///
    /// # Panics
    ///
    /// Panics if number of local or remote nonces passed in does not align with the parties in
    /// `keylist`.
    ///
    /// [`start_encrypted_sign_session_deterministic`]: Self::start_sign_session_deterministic
    /// [`adaptor`]: crate::adaptor
    pub fn start_encrypted_sign_session(
        &self,
        keylist: &KeyList,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy>,
    ) -> Option<SignSession<Adaptor>> {
        let (b, c, public_nonces, R, nonce_needs_negation) =
            self._start_sign_session(keylist, nonces, message, encryption_key)?;
        Some(SignSession {
            b,
            c,
            // local_secret_nonce,
            public_nonces,
            R,
            nonce_needs_negation,
            signing_type: Adaptor {
                y_needs_negation: nonce_needs_negation,
            },
        })
    }

    fn _start_sign_session(
        &self,
        keylist: &KeyList,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    ) -> Option<(
        Scalar<Public, Zero>,
        Scalar<Public, Zero>,
        Vec<Nonce>,
        Point<EvenY>,
        bool,
    )> {
        let mut Rs = nonces;
        let agg_Rs = Rs
            .iter()
            .fold([Point::zero().mark::<Jacobian>(); 2], |acc, nonce| {
                [
                    g!({ acc[0] } + { nonce.0[0] }),
                    g!({ acc[1] } + { nonce.0[1] }),
                ]
            });
        let agg_Rs = [
            g!({ agg_Rs[0] } + encryption_key)
                .normalize()
                .mark::<NonZero>()?,
            agg_Rs[1].normalize().mark::<NonZero>()?,
        ];

        let b = {
            let H = self.nonce_coeff_hash.clone();
            Scalar::from_hash(H.add(agg_Rs).add(keylist.agg_public_key()).add(message))
        }
        .mark::<(Public, Zero)>();

        let (R, r_needs_negation) = g!({ agg_Rs[0] } + b * { agg_Rs[1] } )
            .normalize()
            .expect_nonzero("computationally unreachable: one of the coefficients is a hash output that commits to both point")
            .into_point_with_even_y();

        for R in &mut Rs {
            R.0[0] = R.0[0].conditional_negate(r_needs_negation);
            R.0[1] = R.0[1].conditional_negate(r_needs_negation);
        }

        let c = self
            .schnorr
            .challenge(R.to_xonly(), keylist.agg_public_key(), message);

        Some((b, c, Rs, R, r_needs_negation))
    }

    /// Generates a partial signature (or partial encrypted signature depending on `T`) for the local_secret_nonce.
    ///
    /// TODO
    /// This can only be called once per session as it clears the session (see also [`clear_secrets`]).
    /// Calling `sign` again will return an empty vector.
    ///
    /// [`clear_secrets`]: SignSession::clear_secrets
    pub fn sign<T>(
        &self,
        keylist: &KeyList,
        my_index: u32,
        secret: &Scalar,
        local_secret_nonce: NonceKeyPair,
        session: &SignSession<T>,
    ) -> Scalar<Public, Zero> {
        let c = session.c;
        let b = session.b;

        let x = secret;
        let mut a = keylist.coefs[my_index as usize];
        a.conditional_negate(keylist.needs_negation);
        let [mut r1, mut r2] = local_secret_nonce.secret.clone();
        r1.conditional_negate(session.nonce_needs_negation);
        r2.conditional_negate(session.nonce_needs_negation);
        s!(c * a * x + r1 + b * r2).mark::<(Public, Zero)>()
    }

    #[must_use]
    /// Verifies a partial signature (or partial encrypted signature depending on `T`).
    ///
    /// You must provide the `index` of the party (the index of the key in `keylist`).
    ///
    /// # Panics
    ///
    /// Panics when `index` is equal to or greater than the number of parties in the keylist.
    pub fn verify_partial_signature<T>(
        &self,
        keylist: &KeyList,
        session: &SignSession<T>,
        index: usize,
        partial_sig: Scalar<Public, Zero>,
    ) -> bool {
        let c = session.c;
        let b = session.b;
        let s = &partial_sig;
        let mut a = keylist.coefs[index].clone();
        a.conditional_negate(keylist.needs_negation);
        let X = keylist.keys().nth(index).unwrap().to_point();
        let [R1, R2] = &session.public_nonces[index].0;
        g!((c * a) * X + R1 + b * R2 - s * G).is_zero()
    }

    /// Combines all the partial signatures into a single `Signature`.
    ///
    /// Note this does not check the validity of any of the partial signatures. You should either check
    /// each one using [`verify_partial_signature`] or use [`verify`] on the returned `Signature` to check validity.
    ///
    /// [`verify`]: crate::Schnorr::verify
    /// [`verify_partial_signature`]: Self::verify_partial_signature
    pub fn combine_partial_signatures(
        &self,
        keylist: &KeyList,
        session: &SignSession<Ordinary>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> Signature {
        let (R, s) = self._combine_partial_signatures(keylist, &session, partial_sigs);
        Signature { R: R.to_xonly(), s }
    }

    /// Combines all the partial encrypted signatures into one encrypted signature.
    ///
    /// Note this does not check the validity of any of the partial signatures. You should either check
    /// each one using [`verify_partial_signature`] or use [`verify_encrypted_signature`] on the returned `Signature` to check validity.
    ///
    /// [`verify_encrypted_signature`]: crate::adaptor::Adaptor::verify_encrypted_signature
    /// [`verify_partial_signature`]: Self::verify_partial_signature
    pub fn combine_partial_encrypted_signatures(
        &self,
        keylist: &KeyList,
        session: &SignSession<Adaptor>,
        partial_encrypted_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> EncryptedSignature {
        let (R, s_hat) =
            self._combine_partial_signatures(keylist, &session, partial_encrypted_sigs);
        EncryptedSignature {
            R,
            s_hat,
            needs_negation: session.signing_type.y_needs_negation,
        }
    }

    fn _combine_partial_signatures<T>(
        &self,
        keylist: &KeyList,
        session: &SignSession<T>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> (Point<EvenY>, Scalar<Public, Zero>) {
        let ck = s!(session.c * keylist.tweak);
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, s| s!(acc + s).mark::<Public>())
            .unwrap_or(Scalar::zero().mark::<Public>());
        let s = s!(sum_s + ck).mark::<Public>();
        (session.R, s)
    }
}

#[cfg(test)]
mod test {
    use crate::adaptor::Adaptor;

    use super::*;
    use secp256kfun::{nonce::Deterministic, proptest::prelude::*};
    use sha2::Sha256;

    proptest! {
        #[test]
        fn musig_prop_test(sk1 in any::<Scalar>(), sk2 in any::<Scalar>(), sk3 in any::<Scalar>(), tweak1 in any::<Scalar<Public, Zero>>(), tweak2 in any::<Scalar<Public, Zero>>(), use_tweak2 in any::<bool>()) {
            let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
                .schnorr
                .new_keypair(sk1);
            let keypair2 = musig
                .schnorr
                .new_keypair(sk2);
            let keypair3 = musig
                .schnorr
                .new_keypair(sk3);
            let mut keylist = musig.new_keylist(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]);

            keylist = keylist.tweak(tweak1).unwrap();
            if use_tweak2 {
                keylist = keylist.tweak(tweak2).unwrap();
            }

            let p1_nonce = musig.gen_nonces(&keypair1.sk, &keylist, b"test");
            let p2_nonce = musig.gen_nonces(&keypair2.sk, &keylist, b"test");
            let p3_nonce = musig.gen_nonces(&keypair3.sk, &keylist, b"test");
            let nonces = vec![p1_nonce.public, p2_nonce.public, p3_nonce.public];

            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let p1_session = musig
                .start_sign_session(
                    &keylist,
                    nonces.clone(),
                    message,
                )
                .unwrap();
            let p2_session = musig
                .start_sign_session(
                    &keylist,
                    nonces.clone(),
                    message,
                )
                .unwrap();
            let p3_session = musig
                .start_sign_session(
                    &keylist,
                    nonces.clone(),
                    message,
                )
                .unwrap();

            let p1_sig = musig.sign(&keylist, 0, &keypair1.sk, p1_nonce, &p1_session);

            assert!(musig.verify_partial_signature(&keylist, &p1_session, 0, p1_sig));
            dbg!(&p1_session, &p2_session);
            dbg!(&p1_sig);
            assert_eq!(p1_session, p2_session);

            assert!(musig.verify_partial_signature(&keylist, &p2_session, 0, p1_sig));
            assert!(musig.verify_partial_signature(&keylist, &p3_session, 0, p1_sig));

            let p2_sig = musig.sign(&keylist, 1, &keypair2.sk, p2_nonce, &p2_session);
            assert!(musig.verify_partial_signature(&keylist, &p1_session, 1, p2_sig));
            let p3_sig = musig.sign(&keylist, 2, &keypair3.sk, p3_nonce, &p3_session);
            assert!(musig.verify_partial_signature(&keylist, &p1_session, 2, p3_sig));

            let partial_sigs = [p1_sig, p2_sig, p3_sig];
            let sig_p1 = musig.combine_partial_signatures(&keylist, &p1_session, partial_sigs);
            let sig_p2 = musig.combine_partial_signatures(&keylist, &p2_session, partial_sigs);
            let sig_p3 = musig.combine_partial_signatures(&keylist, &p3_session, partial_sigs);
            assert_eq!(sig_p1, sig_p2);
            assert_eq!(sig_p1, sig_p3);

            assert!(musig
                    .schnorr
                    .verify(&keylist.agg_verification_key(), message, &sig_p1));
            assert!(musig
                    .schnorr
                    .verify(&keylist.agg_verification_key(), message, &sig_p2));
            assert!(musig
                        .schnorr
                        .verify(&keylist.agg_verification_key(), message, &sig_p3));
        }
    }
}
