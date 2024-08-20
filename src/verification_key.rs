use ark_serialize::CanonicalDeserialize;
use proof_of_sql::proof_primitive::dory::{DoryVerifierPublicSetup, VerifierSetup};

use crate::VerifyError;

pub struct VerificationKey<const N: usize>(VerifierSetup);

impl<const N: usize> TryFrom<&[u8]> for VerificationKey<N> {
    type Error = VerifyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 15408 {
            return Err(VerifyError::InvalidVerificationKey);
        }

        let setup: VerifierSetup = CanonicalDeserialize::deserialize_compressed(value)
            .map_err(|_| VerifyError::InvalidVerificationKey)?;

        Ok(Self(setup))
    }
}

impl<const N: usize> VerificationKey<N> {
    pub fn new(setup: VerifierSetup) -> Self {
        Self(setup)
    }

    pub fn into_dory_verifier_public_setup(&self) -> DoryVerifierPublicSetup<'_> {
        DoryVerifierPublicSetup::new(&self.0, N)
    }
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
        let dory_key = verification_key.into_dory_verifier_public_setup();

        assert_eq!(dory_key.verifier_setup(), &vs);
    }
}
