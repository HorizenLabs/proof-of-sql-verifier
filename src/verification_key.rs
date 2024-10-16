// Copyright 2024, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::vec::Vec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proof_of_sql::proof_primitive::dory::{
    DoryVerifierPublicSetup, PublicParameters, VerifierSetup,
};

use crate::VerifyError;

const GT_SERIALIZED_SIZE: usize = 576;
const G1_AFFINE_SERIALIZED_SIZE: usize = 48;
const G2_AFFINE_SERIALIZED_SIZE: usize = 96;

/// Represents a verification key for Dory proofs.
///
/// This structure wraps a `VerifierSetup` and provides methods for
/// creating, deserializing, and converting the verification key.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerificationKey {
    setup: VerifierSetup,
    sigma: usize,
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = VerifyError;

    /// Attempts to create a VerificationKey from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte slice containing the serialized verification key.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Self::Error>` - A VerificationKey if deserialization succeeds, or a VerifyError if it fails.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        VerificationKey::deserialize_compressed_unchecked(value)
            .map_err(|_| VerifyError::InvalidVerificationKey)
    }
}

impl VerificationKey {
    /// Creates a new VerificationKey from PublicParameters.
    ///
    /// # Arguments
    ///
    /// * `params` - A reference to PublicParameters.
    ///
    /// # Returns
    ///
    /// A new VerificationKey instance.
    pub fn new(params: &PublicParameters, sigma: usize) -> Self {
        Self {
            setup: VerifierSetup::from(params),
            sigma,
        }
    }

    /// Converts the verification key into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Converts the VerificationKey into a DoryVerifierPublicSetup.
    ///
    /// # Returns
    ///
    /// A DoryVerifierPublicSetup instance.
    pub(crate) fn to_dory(&self) -> DoryVerifierPublicSetup<'_> {
        DoryVerifierPublicSetup::new(&self.setup, self.sigma)
    }

    /// Computes the serialized size of a VerificationKey.
    ///
    /// # Arguments
    ///
    /// * `max_nu`
    ///
    /// # Returns
    ///
    /// The size in bytes of the serialized VerificationKey.
    pub fn serialized_size(max_nu: usize) -> usize {
        5 * (size_of::<usize>() + (max_nu + 1) * GT_SERIALIZED_SIZE) // Delta_1L, Delta_1R, Delta_2L, Delta_2R, chi
        + 2 * G1_AFFINE_SERIALIZED_SIZE// Gamma_1_0, H_1
        + 3 * G2_AFFINE_SERIALIZED_SIZE // Gamma_2_0, H_2, Gamma_2_fin
        + GT_SERIALIZED_SIZE // H_T
        + 2 * size_of::<usize>() // max_nu, sigma
    }
}

#[cfg(test)]
mod test {
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;
    use proof_of_sql::proof_primitive::dory::PublicParameters;
    use rstest::*;

    use super::*;

    #[test]
    fn verification_key() {
        let public_parameters = PublicParameters::test_rand(4, &mut test_rng());
        let vk = VerificationKey::new(&public_parameters, 1);
        let serialized_vk = vk.to_bytes();
        let deserialized_vk = VerificationKey::try_from(serialized_vk.as_slice()).unwrap();
        let dory_key = deserialized_vk.to_dory();

        assert_eq!(dory_key.verifier_setup(), &vk.setup);
    }

    #[test]
    fn verification_key_short_buffer() {
        let public_parameters = PublicParameters::test_rand(4, &mut test_rng());
        let vk = VerificationKey::new(&public_parameters, 1);
        let serialized_vk = vk.to_bytes();
        let deserialized_vk = VerificationKey::try_from(&serialized_vk[..serialized_vk.len() - 1]);
        assert!(deserialized_vk.is_err());
    }

    #[test]
    fn gt_serialized_size() {
        type GT = ark_ec::pairing::PairingOutput<ark_bls12_381::Bls12_381>;
        let gt = GT::default();
        let mut buffer = Vec::new();
        gt.serialize_compressed(&mut buffer).unwrap();
        assert_eq!(GT_SERIALIZED_SIZE, buffer.len());
    }

    #[test]
    fn g1_affine_serialized_size() {
        type G1Affine = ark_ec::models::bls12::G1Affine<ark_bls12_381::Config>;
        let g1_affine = G1Affine::default();
        let mut buffer = Vec::new();
        g1_affine.serialize_compressed(&mut buffer).unwrap();
        assert_eq!(G1_AFFINE_SERIALIZED_SIZE, buffer.len());
    }

    #[test]
    fn g2_affine_serialized_size() {
        type G2Affine = ark_ec::models::bls12::G2Affine<ark_bls12_381::Config>;
        let g2_affine = G2Affine::default();
        let mut buffer = Vec::new();
        g2_affine.serialize_compressed(&mut buffer).unwrap();
        assert_eq!(G2_AFFINE_SERIALIZED_SIZE, buffer.len());
    }

    #[rstest]
    #[case::max_nu_0(0)]
    #[case::max_nu_1(1)]
    #[case::max_nu_2(2)]
    #[case::max_nu_5(5)]
    fn verification_key_size(#[case] max_nu: usize) {
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let vk = VerificationKey::new(&public_parameters, 1);
        let vk_serialized = vk.to_bytes();
        assert_eq!(
            vk_serialized.len(),
            VerificationKey::serialized_size(max_nu)
        )
    }
}
