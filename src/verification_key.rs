// Copyright 2024, The Horizen Foundation
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

use ark_serialize::CanonicalDeserialize;
use proof_of_sql::proof_primitive::dory::{
    DoryVerifierPublicSetup, PublicParameters, VerifierSetup,
};

use crate::VerifyError;

/// Represents a verification key for Dory proofs.
///
/// This structure wraps a `VerifierSetup` and provides methods for
/// creating, deserializing, and converting the verification key.
///
/// # Type Parameters
///
/// * `N` - A const generic parameter representing the size of the verification key.
pub struct VerificationKey<const N: usize>(VerifierSetup);

impl<const N: usize> TryFrom<&[u8]> for VerificationKey<N> {
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
        let setup = VerifierSetup::deserialize_compressed(value)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;

        // read last usize from the buffer as max_nu is the last field in the struct, and check if it matches N
        // max_nu is not accessible from the VerifierSetup struct, so we need to check it from the buffer
        let max_nu = slice_to_usize(&value[value.len() - std::mem::size_of::<usize>()..]);
        if max_nu != N {
            return Err(VerifyError::InvalidVerificationKey);
        }

        Ok(Self(setup))
    }
}

impl<const N: usize> VerificationKey<N> {
    /// Creates a new VerificationKey from PublicParameters.
    ///
    /// # Arguments
    ///
    /// * `params` - A reference to PublicParameters.
    ///
    /// # Returns
    ///
    /// A new VerificationKey instance.
    pub fn new(params: &PublicParameters) -> Self {
        Self(VerifierSetup::from(params))
    }

    /// Converts the VerificationKey into a DoryVerifierPublicSetup.
    ///
    /// # Returns
    ///
    /// A DoryVerifierPublicSetup instance.
    pub fn into_dory(&self) -> DoryVerifierPublicSetup<'_> {
        DoryVerifierPublicSetup::new(&self.0, N)
    }
}

/// Converts a byte slice to a usize.
///
/// # Arguments
///
/// * `slice` - The byte slice to convert.
///
/// # Returns
///
/// The usize value represented by the byte slice.
fn slice_to_usize(slice: &[u8]) -> usize {
    let mut array = [0u8; std::mem::size_of::<usize>()];
    let len = slice.len().min(std::mem::size_of::<usize>());
    array[..len].copy_from_slice(&slice[..len]);

    usize::from_le_bytes(array)
}

#[cfg(test)]
mod test {
    use ark_serialize::CanonicalSerialize;
    use proof_of_sql::proof_primitive::dory::{test_rng, PublicParameters};

    use super::*;

    #[test]
    fn test_verification_key() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let vs: VerifierSetup = VerifierSetup::from(&public_parameters);
        let mut writer = Vec::new();
        vs.serialize_compressed(&mut writer).unwrap();

        let verification_key = VerificationKey::<4>::try_from(writer.as_ref()).unwrap();
        let dory_key = verification_key.into_dory();

        assert_eq!(dory_key.verifier_setup(), &vs);
    }

    #[test]
    fn test_verification_key_short_buffer() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let vs: VerifierSetup = VerifierSetup::from(&public_parameters);
        let mut writer = Vec::new();
        vs.serialize_compressed(&mut writer).unwrap();

        let verification_key = VerificationKey::<4>::try_from(&writer[..writer.len() - 1]);
        assert!(verification_key.is_err());
    }
}
