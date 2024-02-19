//! Utilities for working with polynomials on the secp256k1 elliptic curve.
//!
//! A polynomial defined by its coefficients a_0, ... a_k. The coefficients can be [`Scalars`] or [`Points`].
//!
//! `f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_k * x^k`
//!
//! [`Scalars`]: crate::Scalar
//! [`Points`]: crate::Point
use crate::{g, marker::*, s, Point, Scalar, G};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::iter;
use rand_core::RngCore;

/// Functions for dealing with scalar polynomials
pub mod scalar {
    use super::*;

    /// Evaluate a scalar polynomial defined by coefficients, at some scalar index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval(poly: &[Scalar], x: Scalar<impl Secrecy, impl ZeroChoice>) -> Scalar<Secret, Zero> {
        s!(powers(x) .* poly)
    }

    /// Create a vector of points by multiplying each scalar by `G`.
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{g, poly, s, Scalar, G};
    /// let secret_poly = (0..5)
    ///     .map(|_| Scalar::random(&mut rand::thread_rng()))
    ///     .collect::<Vec<_>>();
    /// let point_poly = poly::scalar::to_point_poly(&secret_poly);
    /// ```
    pub fn to_point_poly(scalar_poly: &[Scalar]) -> Vec<Point> {
        scalar_poly.iter().map(|a| g!(a * G).normalize()).collect()
    }

    /// Generate a [`Scalar`] polynomial for key generation
    ///
    /// [`Scalar`]: crate::Scalar
    pub fn generate(threshold: usize, rng: &mut impl RngCore) -> Vec<Scalar> {
        (0..threshold).map(|_| Scalar::random(rng)).collect()
    }

    /// Interpolate a set of points and evaluate the polynomial at zero.
    ///
    /// This is useful for interpolating a set of Sharmir Secret Shares to find the joint secret.
    /// Each shamir secret share is associated with a participant index (index, share).
    ///
    /// ## Panics
    ///
    /// Panics if the indicies are not unique.
    pub fn interpolate_and_eval_poly_at_0(
        secrets_at_indices: Vec<(Scalar<Public>, Scalar<Secret, impl ZeroChoice>)>,
    ) -> Scalar<Secret, Zero> {
        let indicies: Vec<_> = secrets_at_indices.iter().map(|(index, _)| *index).collect();
        secrets_at_indices
            .into_iter()
            .map(|(index, secret)| {
                let lambda = eval_basis_poly_at_0(index, indicies.iter());
                s!(secret * lambda)
            })
            .fold(s!(0), |acc, contribution| s!(acc + contribution))
    }
}

/// Functions for dealing with point polynomials
pub mod point {
    use super::*;

    /// Evaluate a point polynomial defined by coefficients, at some index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval<T: PointType>(
        poly: &[Point<T, Public, impl ZeroChoice>],
        x: Scalar<Public, impl ZeroChoice>,
    ) -> Point<NonNormal, Public, Zero> {
        g!(powers(x) .* poly)
    }

    /// Add the coefficients of two point polynomials.
    ///
    /// Handles mismatched polynomial lengths.
    pub fn add<T: PointType + Default, S: Secrecy, Z: ZeroChoice>(
        poly1: &[Point<T, S, Z>],
        poly2: &[Point<T, S, Z>],
    ) -> Vec<Point<NonNormal, Public, Zero>> {
        let (long, short) = if poly1.len() >= poly2.len() {
            (poly1, poly2)
        } else {
            (poly2, poly1)
        };

        long.iter()
            .map(|c| c.mark_zero())
            .zip(
                short
                    .iter()
                    .map(|c| c.mark_zero())
                    .chain(iter::repeat(Point::zero())),
            )
            .map(|(c1, c2)| g!(c1 + c2))
            .collect()
    }

    /// Find the coefficients of the polynomial that interpolates a set of points (index, point).
    ///
    /// Panics if the indicies are not unique.
    ///
    /// A vector with a tail of zero coefficients means the interpolation was overdetermined.
    pub fn interpolate(
        points_at_indicies: Vec<(Scalar<Public, impl ZeroChoice>, Point)>,
    ) -> Vec<Point<impl PointType, Public, Zero>> {
        // let (indicies, points): (Vec<_>, Vec<_>) = points_at_indicies.into_iter().unzip();

        let mut interpolating_polynomial = Vec::with_capacity(points_at_indicies.len());
        for (j, (x_j, y_j)) in points_at_indicies.iter().enumerate() {
            // Basis polynomial calculated from the product of these indices coefficients:
            //      l_j(x) = Product[ (x-x_m)/(x_j-x_m), j!=m ]
            // Or
            //      l_j(x) = Product[ a_m*x + b_m, j!=m], where a_m = 1/(x_j-x_m) and b_m = -x_m*a_m.
            let mut basis_polynomial: Vec<_> = vec![];
            for (_, x_m) in points_at_indicies
                .iter()
                .map(|(x_m, _)| x_m)
                .enumerate()
                .filter(|(m, _)| *m != j)
            {
                let a_m = s!(x_j - x_m)
                    .non_zero()
                    .expect("points must lie at unique indicies to interpolate")
                    .invert();
                let b_m = s!(-x_m * a_m).mark_zero();

                // Multiply out the product. Beginning with the first two coefficients
                // we then take the next set (b_1, a_1), multiply through, and collect terms.
                if basis_polynomial.is_empty() {
                    basis_polynomial.extend([b_m.mark_zero().public(), a_m.mark_zero().public()])
                } else {
                    let mut prev_coeff = s!(0).public();
                    for coeff in basis_polynomial.iter_mut() {
                        let bumping_up_degree = s!(prev_coeff * a_m);
                        prev_coeff = *coeff;

                        let same_degree = s!(prev_coeff * b_m);
                        *coeff = s!(same_degree + bumping_up_degree).public();
                    }
                    let higher_degree = s!(prev_coeff * a_m);
                    basis_polynomial.push(higher_degree.public());
                }
            }

            let point_scaled_basis_polynomial = basis_polynomial
                .iter()
                .map(|coeff| g!(coeff * y_j).mark_zero())
                .collect::<Vec<_>>();

            interpolating_polynomial =
                self::add(&interpolating_polynomial, &point_scaled_basis_polynomial)
        }

        interpolating_polynomial
    }
}
/// Returns an iterator of 1, x, x², x³ ...
fn powers<S: Secrecy, Z: ZeroChoice>(x: Scalar<S, Z>) -> impl Iterator<Item = Scalar<S, Z>> {
    core::iter::successors(Some(Scalar::one().mark_zero_choice::<Z>()), move |xpow| {
        Some(s!(xpow * x).set_secrecy())
    })
}

/// Evaluate the lagrange basis polynomial for the x coordinate x_j interpolated with the nodes x_ms at 0.
///
/// Described as the lagrange coefficient in FROST. Useful when interpolating a sharmir shared
/// secret which usually lies at the value of the polynomial evaluated at 0.
pub fn eval_basis_poly_at_0<'a>(
    x_j: Scalar<impl Secrecy>,
    x_ms: impl Iterator<Item = &'a Scalar<impl Secrecy>>,
) -> Scalar<Public> {
    x_ms.filter(|x_m| *x_m != &x_j)
        .fold(Scalar::one(), |acc, x_m| {
            let denominator = s!(x_m - x_j)
                .non_zero()
                .expect("we filtered duplicate indicies");
            s!(acc * x_m / denominator).public()
        })
}
