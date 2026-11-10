//! Keys used by generation without handing out their bytes.
//!
//! [`KeyProvider`] hands out a key's 32 bytes, which a store whose keys cannot leave it
//! (a browser's WebCrypto keys made non-extractable, a hardware key) cannot do. [`KeyOps`]
//! asks the store to do the operation instead: seal, open and authenticate with the key of
//! a generation. Every [`KeyProvider`] is a [`KeyOps`] (the blanket implementation below
//! takes the key's bytes and calls [`crate::stream`] and [`crate::mac`]), so code written
//! against [`KeyOps`] runs on every store, and on a [`KeyProvider`] it produces exactly what
//! calling those functions directly produces (`tests/key_ops_native_bytes.rs`).
//!
//! [`AsyncKeyOps`] is the same contract with each operation returning a future, for stores
//! whose operations are asynchronous (WebCrypto returns promises). Every [`KeyOps`] is an
//! [`AsyncKeyOps`] whose futures are ready at once. The futures are not required to be
//! `Send`: a browser runs them on its one thread.
//!
//! The caller asks for the current generation first and seals under it, so that it can
//! bind the generation into the associated data it passes.

use alloc::vec::Vec;
use core::future::Future;

use crate::keystore::{KeyGeneration, KeyProvider, KeyProviderError};

/// Why a key operation failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOpsError {
    /// The key of the generation could not be used (see [`KeyProviderError`]).
    Key(KeyProviderError),
    /// The sealed value did not open: it was changed, sealed under another key or with
    /// other associated data, or it is not a sealed value.
    Open,
    /// The store could not seal (its random source or its cipher failed).
    Seal,
}

impl From<KeyProviderError> for KeyOpsError {
    fn from(e: KeyProviderError) -> Self {
        Self::Key(e)
    }
}

impl core::fmt::Display for KeyOpsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Key(e) => write!(f, "{e}"),
            Self::Open => f.write_str("the sealed value did not open"),
            Self::Seal => f.write_str("the value could not be sealed"),
        }
    }
}

#[cfg(feature = "std-base")]
impl std::error::Error for KeyOpsError {}

/// The context under which the blanket implementation derives a generation's MAC key from
/// its 32 bytes, so that the same bytes are never used both to seal and to authenticate.
#[cfg(feature = "hash")]
pub const KEY_OPS_MAC_CONTEXT: &str = "alice-crypto key-ops mac v1";

/// Seal, open and authenticate with the keys of a store, by generation.
pub trait KeyOps: Send + Sync {
    /// The generation new values are sealed under.
    ///
    /// # Errors
    ///
    /// [`KeyOpsError::Key`] with [`KeyProviderError::Unavailable`] when there is no usable
    /// current key.
    fn current_generation(&self) -> Result<KeyGeneration, KeyOpsError>;

    /// `plaintext` sealed with the key of `generation`, bound to `aad`.
    ///
    /// # Errors
    ///
    /// [`KeyOpsError::Key`] when that key cannot be used, [`KeyOpsError::Seal`] when sealing
    /// failed.
    fn seal(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError>;

    /// The plaintext of a value [`Self::seal`] made under `generation` with `aad`.
    ///
    /// # Errors
    ///
    /// [`KeyOpsError::Key`] when that key cannot be used, [`KeyOpsError::Open`] when the
    /// value does not open.
    fn open(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError>;

    /// A 32-byte tag of `message` under `context` with the MAC key of `generation`.
    ///
    /// # Errors
    ///
    /// [`KeyOpsError::Key`] when that key cannot be used.
    #[cfg(feature = "hash")]
    fn mac(
        &self,
        generation: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; 32], KeyOpsError>;
}

/// [`KeyOps`] with operations that complete later.
pub trait AsyncKeyOps {
    /// See [`KeyOps::current_generation`].
    fn current_generation(&self) -> impl Future<Output = Result<KeyGeneration, KeyOpsError>>;

    /// See [`KeyOps::seal`].
    fn seal(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, KeyOpsError>>;

    /// See [`KeyOps::open`].
    fn open(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, KeyOpsError>>;

    /// See [`KeyOps::mac`].
    #[cfg(feature = "hash")]
    fn mac(
        &self,
        generation: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> impl Future<Output = Result<[u8; 32], KeyOpsError>>;
}

impl<P: KeyProvider + ?Sized> KeyOps for P {
    fn current_generation(&self) -> Result<KeyGeneration, KeyOpsError> {
        Ok(self.current()?.0)
    }

    fn seal(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        let key = self.by_generation(generation)?;
        crate::stream::seal_with_aad(&key, aad, plaintext).map_err(|_| KeyOpsError::Seal)
    }

    fn open(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyOpsError> {
        let key = self.by_generation(generation)?;
        crate::stream::open_with_aad(&key, aad, sealed).map_err(|_| KeyOpsError::Open)
    }

    #[cfg(feature = "hash")]
    fn mac(
        &self,
        generation: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; 32], KeyOpsError> {
        let key = self.by_generation(generation)?;
        let mac_key = crate::mac::MacKey::from_bytes(crate::hash::derive_key(
            KEY_OPS_MAC_CONTEXT,
            key.as_bytes(),
        ));
        Ok(*crate::mac::mac_with_context(&mac_key, context, message).as_bytes())
    }
}

impl<T: KeyOps + ?Sized> AsyncKeyOps for T {
    fn current_generation(&self) -> impl Future<Output = Result<KeyGeneration, KeyOpsError>> {
        core::future::ready(KeyOps::current_generation(self))
    }

    fn seal(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, KeyOpsError>> {
        core::future::ready(KeyOps::seal(self, generation, aad, plaintext))
    }

    fn open(
        &self,
        generation: KeyGeneration,
        aad: &[u8],
        sealed: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, KeyOpsError>> {
        core::future::ready(KeyOps::open(self, generation, aad, sealed))
    }

    #[cfg(feature = "hash")]
    fn mac(
        &self,
        generation: KeyGeneration,
        context: &[u8],
        message: &[u8],
    ) -> impl Future<Output = Result<[u8; 32], KeyOpsError>> {
        core::future::ready(KeyOps::mac(self, generation, context, message))
    }
}
