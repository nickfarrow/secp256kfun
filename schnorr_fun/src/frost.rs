#![allow(missing_docs)]
use core::iter;
use std::collections::HashMap;

use crate::{
    musig::{Nonce, NonceKeyPair},
    KeyPair, Message, Schnorr, Signature, Vec,
};
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::HashAdd,
    marker::*,
    nonce::NonceGen,
    rand_core, s, Point, Scalar, G,
};

#[derive(Clone, Debug, Default)]
pub struct Frost<SS, H> {
    pub schnorr: SS,
    pub nonce_coeff_hash: H,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
    pub fn eval(&self, x: u32) -> Scalar<Secret, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let mut xpow = s!(1).mark::<Public>();
        self.0
            .iter()
            .skip(1)
            .fold(self.0[0].clone().mark::<Zero>(), move |sum, coeff| {
                xpow = s!(xpow * x).mark::<Public>();
                s!(sum + xpow * coeff)
            })
    }

    pub fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    pub fn random(n_coefficients: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn first_coef(&self) -> &Scalar {
        &self.0[0]
    }

    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }
}

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
    Vec<Point<Normal, Public, Z>>,
);

impl<Z> PointPoly<Z> {
    pub fn eval(&self, x: u32) -> Point<Jacobian, Public, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let xpows = iter::successors(Some(s!(1).mark::<Public>()), |xpow| {
            Some(s!(x * xpow).mark::<Public>())
        })
        .take(self.0.len())
        .collect::<Vec<_>>();
        crate::fun::op::lincomb(&xpows, &self.0)
    }

    fn combine(mut polys: impl Iterator<Item = Self>) -> PointPoly<Zero> {
        let mut combined_poly = polys
            .next()
            .expect("cannot combine empty list of polys")
            .0
            .into_iter()
            .map(|p| p.mark::<(Jacobian, Zero)>())
            .collect::<Vec<_>>();
        for poly in polys {
            for (combined_point, point) in combined_poly.iter_mut().zip(poly.0) {
                *combined_point = g!({ *combined_point } + point);
            }
        }
        PointPoly(combined_poly.into_iter().map(|p| p.normalize()).collect())
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn points(&self) -> &[Point<Normal, Public, Z>] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Dkg {
    point_polys: Vec<PointPoly>,
    needs_negation: bool,
    joint_key: JointKey,
}

impl Dkg {
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

#[derive(Debug, Clone)]
pub enum FirstRoundError {
    PolyDifferentLength(usize),
    NotEnoughParties,
    ZeroJointKey,
    ZeroVerificationShare,
}

impl core::fmt::Display for FirstRoundError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use FirstRoundError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroJointKey => write!(f, "The joint key was zero. This means one of the parties was possibly malicious and you are not protecting against this properly"),
            ZeroVerificationShare => write!(f, "One of the verification shares was malicious so we must abort the protocol"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FirstRoundError {}

#[derive(Debug, Clone)]
pub enum SecondRoundError {
    InvalidShare(usize),
}

impl core::fmt::Display for SecondRoundError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use SecondRoundError::*;
        match self {
            InvalidShare(i) => write!(f, "the share provided by party at index {} was invalid", i),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecondRoundError {}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct JointKey {
    joint_public_key: Point<EvenY>,
    verification_shares: Vec<Point>,
    threshold: usize,
}

impl<SS, H> Frost<SS, H> {
    pub fn create_shares(
        &self,
        dkg: &Dkg,
        mut scalar_poly: ScalarPoly,
    ) -> Vec<Scalar<Secret, Zero>> {
        scalar_poly.0[0].conditional_negate(dkg.needs_negation);
        (1..=dkg.point_polys.len())
            .map(|i| scalar_poly.eval(i as u32))
            .collect()
    }
}

impl<SS, H> Frost<SS, H> {
    pub fn collect_polys(&self, mut point_polys: Vec<PointPoly>) -> Result<Dkg, FirstRoundError> {
        {
            let len_first_poly = point_polys[0].poly_len();
            if let Some((i, _)) = point_polys
                .iter()
                .enumerate()
                .find(|(i, point_poly)| point_poly.poly_len() != len_first_poly)
            {
                return Err(FirstRoundError::PolyDifferentLength(i));
            }

            if point_polys.len() < len_first_poly {
                return Err(FirstRoundError::NotEnoughParties);
            }
        }

        let mut joint_poly = PointPoly::combine(point_polys.clone().into_iter());
        let joint_key = joint_poly.0[0];

        let (joint_public_key, needs_negation) = joint_key
            .mark::<NonZero>()
            .ok_or(FirstRoundError::ZeroJointKey)?
            .into_point_with_even_y();

        for poly in &mut point_polys {
            poly.0[0] = poly.0[0].conditional_negate(needs_negation);
        }
        joint_poly.0[0] = joint_poly.0[0].conditional_negate(needs_negation);

        let verification_shares = (1..=point_polys.len())
            .map(|i| joint_poly.eval(i as u32).normalize().mark::<NonZero>())
            .collect::<Option<Vec<Point>>>()
            .ok_or(FirstRoundError::ZeroVerificationShare)?;

        Ok(Dkg {
            point_polys,
            needs_negation,
            joint_key: JointKey {
                verification_shares,
                joint_public_key,
                threshold: joint_poly.poly_len(),
            },
        })
    }

    pub fn collect_shares(
        &self,
        dkg: Dkg,
        my_index: usize,
        secret_shares: Vec<Scalar<Secret, Zero>>,
    ) -> Result<(Scalar, JointKey), SecondRoundError> {
        assert_eq!(secret_shares.len(), dkg.joint_key.verification_shares.len());
        let mut total_secret_share = s!(0);
        for (i, (secret_share, poly)) in secret_shares.iter().zip(&dkg.point_polys).enumerate() {
            let expected_public_share = poly.eval((my_index + 1) as u32);
            if g!(secret_share * G) != expected_public_share {
                return Err(SecondRoundError::InvalidShare(i));
            }
            let (verification_key, _) = poly.0[0].into_point_with_even_y();

            total_secret_share = s!(total_secret_share + secret_share);
        }

        let total_secret_share = total_secret_share.expect_nonzero(
            "since verification shares are non-zero, corresponding secret shares cannot be zero",
        );

        Ok((total_secret_share, dkg.joint_key))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignSession {
    binding_coeff: Scalar,
    nonces_need_negation: bool,
    agg_nonce: Point<EvenY>,
    challenge: Scalar,
    nonces: HashMap<u32, Nonce>,
}

impl<H: Digest<OutputSize = U32> + Clone, CH: Digest<OutputSize = U32> + Clone, NG>
    Frost<Schnorr<CH, NG>, H>
{
    fn lagrange_lambda(&self, my_index: usize, nonces: &HashMap<u32, Nonce>) -> Scalar {
        // Change to handle multiple my_indexes
        // https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
        // Change to one inverse
        let k = Scalar::from(1 + my_index as u32);
        nonces
            .iter()
            .map(|(j, _)| 1 + *j)
            .filter(|j| Scalar::from(*j) != k)
            .map(|j| Scalar::from(j as u32).expect_nonzero("index can not be zero"))
            .fold(Scalar::one(), |acc, j| {
                let denominator = s!(j - k)
                    .expect_nonzero("removed duplicate indexes")
                    .invert();
                s!(acc * j * denominator)
            })
    }

    pub fn start_sign_session(
        &self,
        joint_key: &JointKey,
        nonces: &[(usize, Nonce)],
        message: Message,
    ) -> SignSession {
        let nonce_map: HashMap<_, _> = nonces
            .into_iter()
            .map(|(i, nonce)| (*i as u32, *nonce))
            .collect();
        assert_eq!(nonces.len(), nonce_map.len());
        assert!(joint_key.threshold <= nonce_map.len());

        // aggregate nonces for signers
        let agg_nonces: Vec<Point> = nonce_map
            .iter()
            .fold([Point::zero().mark::<Jacobian>(); 2], |acc, (_, nonce)| {
                [
                    g!({ acc[0] } + { nonce.0[0] }),
                    g!({ acc[1] } + { nonce.0[1] }),
                ]
            })
            .iter()
            .map(|agg_nonce| {
                agg_nonce
                    .normalize()
                    .mark::<NonZero>()
                    .expect("aggregate nonce should be non-zero")
            })
            .collect();

        let agg_nonce_points: [Point; 2] = [agg_nonces[0], agg_nonces[1]];
        let binding_coeff = Scalar::from_hash(
            self.nonce_coeff_hash
                .clone()
                .add(agg_nonce_points[0])
                .add(agg_nonce_points[1])
                .add(joint_key.joint_public_key)
                .add(message),
        );

        let (combined_agg_nonce, nonces_need_negation) =
            g!({ agg_nonce_points[0] } + binding_coeff * { agg_nonce_points[1] })
                .normalize()
                .expect_nonzero("impossibly unlikely, input is a hash")
                .into_point_with_even_y();

        let challenge = Scalar::from_hash(
            self.schnorr
                .challenge_hash()
                .add(combined_agg_nonce)
                .add(joint_key.joint_public_key)
                .add(message),
        );

        SignSession {
            binding_coeff,
            nonces_need_negation,
            agg_nonce: combined_agg_nonce,
            challenge,
            nonces: nonce_map,
        }
    }

    pub fn sign(
        &self,
        // joint_key: &JointKey,
        session: &SignSession,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonces: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        let lambda = self.lagrange_lambda(my_index, &session.nonces);
        let [mut r1, mut r2] = secret_nonces.secret;
        r1.conditional_negate(session.nonces_need_negation);
        r2.conditional_negate(session.nonces_need_negation);

        let b = &session.binding_coeff;
        let x = secret_share;
        let c = &session.challenge;
        dbg!(
            &my_index,
            &lambda,
            &c,
            &b,
            &x,
            &r1,
            &r2,
            g!(x * G),
            g!(r1 * G),
            g!(r2 * G)
        );
        dbg!();
        s!(r1 + (r2 * b) + lambda * x * c).mark::<Public>()
    }

    #[must_use]
    pub fn verify_signature_share(
        &self,
        joint_key: &JointKey,
        session: &SignSession,
        index: usize,
        signature_share: Scalar<Public, Zero>,
    ) -> bool {
        let s = signature_share;
        let lambda = self.lagrange_lambda(index, &session.nonces);
        let c = &session.challenge;
        let b = &session.binding_coeff;
        let X = joint_key.verification_shares[index];
        let [ref R1, ref R2] = session
            .nonces
            .get(&(index as u32))
            .expect("verifying index that is not part of signing coalition")
            .0;

        dbg!(&index, &s, &lambda, &c, &b, &X, &R1, &R2);
        dbg!();
        dbg!();

        g!(R1 + b * R2 + (c * lambda) * X - s * G).is_zero()
    }

    pub fn combine_signature_shares(
        &self,
        session: &SignSession,
        partial_sigs: Vec<Scalar<Public, Zero>>,
    ) -> Signature {
        // TODO add tweak term
        // Work with iterators or [], return sig or scalar

        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, partial_sig| s!(acc + partial_sig).mark::<Public>())
            .unwrap_or(Scalar::zero().mark::<Public>());

        Signature {
            R: session.agg_nonce.to_xonly(),
            s: sum_s,
        }
    }
}

impl<H: Digest<OutputSize = U32> + Clone, CH: Digest<OutputSize = U32> + Clone, NG: NonceGen>
    Frost<Schnorr<CH, NG>, H>
{
    pub fn gen_nonce(
        &self,
        joint_key: &JointKey,
        my_index: usize,
        secret_share: &Scalar,
        sid: &[u8],
    ) -> NonceKeyPair {
        let r1 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret_share,
            public => [ b"r1-frost", my_index.to_be_bytes(), joint_key.joint_public_key, &joint_key.verification_shares[..], sid]
        );
        let r2 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret_share,
            public => [ b"r2-frost", my_index.to_be_bytes(), joint_key.joint_public_key, &joint_key.verification_shares[..], sid]
        );
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use secp256kfun::{nonce::Deterministic, proptest::prelude::*};
    use sha2::Sha256;

    #[test]
    fn frost_test_end_to_end() {
        // Create a secret polynomial for each participant
        let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
        let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
        let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);
        //
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>::default();
        let point_polys = vec![
            sp1.to_point_poly(),
            sp2.to_point_poly(),
            sp3.to_point_poly(),
        ];

        let dkg = frost.collect_polys(point_polys).unwrap();
        let shares1 = frost.create_shares(&dkg, sp1);
        let shares2 = frost.create_shares(&dkg, sp2);
        let shares3 = frost.create_shares(&dkg, sp3);

        let (secret_share1, joint_key) = frost
            .collect_shares(
                dkg.clone(),
                0,
                vec![shares1[0].clone(), shares2[0].clone(), shares3[0].clone()],
            )
            .unwrap();
        let (secret_share2, jk2) = frost
            .collect_shares(
                dkg.clone(),
                1,
                vec![shares1[1].clone(), shares2[1].clone(), shares3[1].clone()],
            )
            .unwrap();
        let (secret_share3, jk3) = frost
            .collect_shares(
                dkg.clone(),
                2,
                vec![shares1[2].clone(), shares2[2].clone(), shares3[2].clone()],
            )
            .unwrap();

        assert_eq!(joint_key, jk2);
        assert_eq!(joint_key, jk3);

        let nonce1 = frost.gen_nonce(&joint_key, 0, &secret_share1, b"test");
        let nonce3 = frost.gen_nonce(&joint_key, 2, &secret_share3, b"test");
        let nonces = [(0, nonce1.public()), (2, nonce3.public())];

        let session =
            frost.start_sign_session(&joint_key, &nonces, Message::plain("test", b"test"));

        dbg!(&session);
        {
            let session2 = frost.start_sign_session(&jk2, &nonces, Message::plain("test", b"test"));
            assert_eq!(session2, session);
        }

        // let sig1 = frost.sign(&joint_key, &session, 0, &secret_share1, nonce1);
        let sig1 = frost.sign(&session, 0, &secret_share1, nonce1);
        let sig3 = frost.sign(&session, 2, &secret_share3, nonce3);

        dbg!(sig1, sig3);

        assert!(frost.verify_signature_share(&joint_key, &session, 0, sig1));
        assert!(frost.verify_signature_share(&joint_key, &session, 2, sig3));
        let combined_sig = frost.combine_signature_shares(&session, vec![sig1, sig3]);

        assert!(frost.schnorr.verify(
            &joint_key.joint_public_key,
            Message::<Public>::plain("test", b"test"),
            &combined_sig
        ));
    }
}