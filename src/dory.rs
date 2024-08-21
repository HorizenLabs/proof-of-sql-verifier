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

use crate::{
    verify_generic::verify_proof, DoryProof, DoryPublicInput, VerificationKey, VerifyError,
};

/// Verifies a Dory proof against the provided public input and verification key.
///
/// # Arguments
///
/// * `proof` - The Dory proof to be verified.
/// * `pubs` - The public input for the proof.
/// * `vk` - The verification key used to verify the proof.
///
/// # Type Parameters
///
/// * `N` - A const generic parameter, likely related to the size of the verification key.
///
/// # Returns
///
/// * `Result<(), VerifyError>` - Ok(()) if the proof is valid, or an error if verification fails.
pub fn verify_dory_proof<const N: usize>(
    proof: &DoryProof,
    pubs: &DoryPublicInput,
    vk: &VerificationKey<N>,
) -> Result<(), VerifyError> {
    verify_proof(
        proof.clone().into_dory(),
        pubs.expr(),
        pubs.commitments(),
        pubs.query_data(),
        &vk.into_dory(),
    )
}
