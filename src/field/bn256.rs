//! BN256 scalar field backed by Lambdaworks Montgomery arithmetic.

use std::ops;

use lambdaworks_math::field::{
    element::FieldElement,
    fields::montgomery_backed_prime_fields::{IsModulus, MontgomeryBackendPrimeField},
};
use lambdaworks_math::unsigned_integer::element::U384;
use serde::Deserialize;

use crate::cs::FieldRepr;
use crate::cs::{error::ConstructionError, Field};

/// Canonical BN256 scalar-field modulus.
pub const BN256_PRIME_FIELD_ORDER: U384 =
    U384::from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

// FPBn256
/// Type-level BN256 scalar-field modulus.
#[derive(Clone, Debug)]
pub struct Bn256FieldModulus;
impl IsModulus<U384> for Bn256FieldModulus {
    const MODULUS: U384 = BN256_PRIME_FIELD_ORDER;
}
type Bn256PrimeFieldBackend = FieldElement<MontgomeryBackendPrimeField<Bn256FieldModulus, 6>>;

/// Canonical integer representation of a BN256 scalar-field element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bn256PrimeFieldRepr(U384);
impl AsRef<[u64]> for Bn256PrimeFieldRepr {
    fn as_ref(&self) -> &[u64] {
        &self.0.limbs[..]
    }
}
impl AsMut<[u64]> for Bn256PrimeFieldRepr {
    fn as_mut(&mut self) -> &mut [u64] {
        &mut self.0.limbs[..]
    }
}
impl ops::Add for Bn256PrimeFieldRepr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Bn256PrimeField::from(self)
            .add(Bn256PrimeField::from(rhs))
            .into()
    }
}
impl ops::Sub for Bn256PrimeFieldRepr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Bn256PrimeField::from(self)
            .sub(Bn256PrimeField::from(rhs))
            .into()
    }
}
impl ops::Mul for Bn256PrimeFieldRepr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Bn256PrimeField::from(self)
            .mul(Bn256PrimeField::from(rhs))
            .into()
    }
}
impl ops::Div for Bn256PrimeFieldRepr {
    type Output = Option<Self>;
    fn div(self, rhs: Self) -> Option<Self> {
        Bn256PrimeField::from(self)
            .div(Bn256PrimeField::from(rhs))
            .map(Into::into)
    }
}
impl ops::Neg for Bn256PrimeFieldRepr {
    type Output = Self;
    fn neg(self) -> Self {
        Bn256PrimeField::from(self).neg().into()
    }
}
impl ops::Shl<usize> for Bn256PrimeFieldRepr {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self {
        Self(self.0.shl(rhs))
    }
}
impl ops::Shr<usize> for Bn256PrimeFieldRepr {
    type Output = Self;
    fn shr(self, rhs: usize) -> Self {
        Self(self.0.shr(rhs))
    }
}
impl ops::BitAnd for Bn256PrimeFieldRepr {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0.bitand(rhs.0))
    }
}
impl ops::BitOr for Bn256PrimeFieldRepr {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        let tmp = U384 {
            limbs: [
                self.0.limbs[0] | rhs.0.limbs[0],
                self.0.limbs[1] | rhs.0.limbs[1],
                self.0.limbs[2] | rhs.0.limbs[2],
                self.0.limbs[3] | rhs.0.limbs[3],
                self.0.limbs[4] | rhs.0.limbs[4],
                self.0.limbs[5] | rhs.0.limbs[5],
            ],
        };
        if tmp >= BN256_PRIME_FIELD_ORDER {
            Self(tmp - BN256_PRIME_FIELD_ORDER)
        } else {
            Self(tmp)
        }
    }
}
impl FieldRepr for Bn256PrimeFieldRepr {}

/// BN256 scalar-field element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bn256PrimeField([u64; 6]);
impl From<Bn256PrimeFieldBackend> for Bn256PrimeField {
    fn from(fe: Bn256PrimeFieldBackend) -> Self {
        Self(fe.value().limbs)
    }
}
impl From<Bn256PrimeField> for Bn256PrimeFieldBackend {
    fn from(value: Bn256PrimeField) -> Self {
        Bn256PrimeFieldBackend::from_raw(&U384 { limbs: value.0 })
    }
}
impl ops::Add for Bn256PrimeField {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let l: Bn256PrimeFieldBackend = self.into();
        let r: Bn256PrimeFieldBackend = rhs.into();
        Self::from(l + r)
    }
}
impl ops::Sub for Bn256PrimeField {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let l: Bn256PrimeFieldBackend = self.into();
        let r: Bn256PrimeFieldBackend = rhs.into();
        Self::from(l - r)
    }
}
impl ops::Mul for Bn256PrimeField {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let l: Bn256PrimeFieldBackend = self.into();
        let r: Bn256PrimeFieldBackend = rhs.into();
        Self::from(l * r)
    }
}
impl ops::Neg for Bn256PrimeField {
    type Output = Self;
    fn neg(self) -> Self {
        let l: Bn256PrimeFieldBackend = self.into();
        Self::from(-l)
    }
}
impl From<Bn256PrimeFieldRepr> for Bn256PrimeField {
    fn from(repr: Bn256PrimeFieldRepr) -> Self {
        Self::from(Bn256PrimeFieldBackend::from(&repr.0))
    }
}
impl From<Bn256PrimeField> for Bn256PrimeFieldRepr {
    fn from(value: Bn256PrimeField) -> Self {
        let tmp: Bn256PrimeFieldBackend = value.into();
        Bn256PrimeFieldRepr(tmp.representative())
    }
}

impl Field for Bn256PrimeField {
    const CAPACITY_BITS: usize = 253;
    type Repr = Bn256PrimeFieldRepr;
    fn one() -> Self {
        Self::from(Bn256PrimeFieldBackend::one())
    }
    fn zero() -> Self {
        Self::from(Bn256PrimeFieldBackend::zero())
    }
    fn neg1() -> Self {
        -Self::one()
    }
    fn inv(self) -> Option<Self> {
        if self == Self::zero() {
            None
        } else {
            Some(Self::from(Bn256PrimeFieldBackend::inv(&self.into())))
        }
    }
    fn div(self, other: Self) -> Option<Self> {
        Some(self * other.inv()?)
    }
    fn from_str(s: &str) -> Result<Self, ConstructionError> {
        let (digits, radix) = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .map_or((s, 10), |digits| (digits, 16));
        if digits.is_empty() {
            return Err(ConstructionError::ParamFormatError);
        }

        let base = U384::from_u64(radix);
        let mut value = U384::from_u64(0);
        for byte in digits.bytes() {
            let digit = match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' if radix == 16 => u64::from(byte - b'a' + 10),
                b'A'..=b'F' if radix == 16 => u64::from(byte - b'A' + 10),
                _ => return Err(ConstructionError::ParamFormatError),
            };
            if digit >= radix {
                return Err(ConstructionError::ParamFormatError);
            }
            let (high, low) = U384::mul(&value, &base);
            if high != U384::from_u64(0) {
                return Err(ConstructionError::ParamFormatError);
            }
            let (next, overflow) = U384::add(&low, &U384::from_u64(digit));
            if overflow {
                return Err(ConstructionError::ParamFormatError);
            }
            value = next;
        }
        if value >= BN256_PRIME_FIELD_ORDER {
            return Err(ConstructionError::ParamFormatError);
        }
        Ok(Self::from(Bn256PrimeFieldBackend::from(&value)))
    }
    fn to_str(self) -> String {
        let l: Bn256PrimeFieldBackend = self.into();
        l.to_string()
    }
}

impl std::str::FromStr for Bn256PrimeField {
    type Err = ConstructionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        <Self as Field>::from_str(value)
    }
}

impl std::fmt::Display for Bn256PrimeField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&<Self as Field>::to_str(*self))
    }
}

impl<'de> Deserialize<'de> for Bn256PrimeField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Bn256PrimeField::from_str(&s).map_err(serde::de::Error::custom)
    }
}
