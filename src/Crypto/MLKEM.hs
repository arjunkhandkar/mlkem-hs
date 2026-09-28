{- |
Module: Crypto.MLKEM
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

ML-KEM is a key encapsulation mechanism deisgned to be resistant to attacks from quantum computers. It was standardised by the NIST as FIPS-203.

This module exports Haskell bindings to the mlkem-native implementation, which is written in C and assembly.
-}
module Crypto.MLKEM
  ( -- * Key pair generation
    keyPair

    -- * Encapsulation and decapsulation
  , encaps
  , decaps

    -- * Constants
  , publicKeyBytes
  , secretKeyBytes
  , ciphertextBytes
  , encapsulationSeedBytes
  , keygenSeedBytes

    -- * Types
  , PublicKey (..)
  , SecretKey (..)
  , Ciphertext (..)
  , SharedSecret (..)

    -- * Errors
  , CryptoError (..)
  ) where

import Control.Exception (Exception, throwIO, try)
import Control.Monad (unless, when)
import Data.ByteArray (ByteArrayAccess, Bytes, ScrubbedBytes, alloc, allocRet, withByteArray)
import Data.ByteArray qualified as ByteArrayAccess
import Foreign (Ptr, Word8, castPtr)
import Foreign.C (CInt (CInt))
import System.IO.Unsafe (unsafePerformIO)

#if MLK_HS_PARAM == 1024

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_keypair_derand"
  mlkem_keypair_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_enc_derand"
  mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_dec"
  mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- | The size of the public key in bytes
--
-- +------------------------------+------------------+
-- | Parameter set                | Key size (bytes) |
-- +==============================+==================+
-- | ML-KEM-512                   | 800              |
-- +------------------------------+------------------+
-- | ML-KEM-768                   | 1184             |
-- +------------------------------+------------------+
-- | __ML-KEM-1024 (configured)__ | __1568__         |
-- +------------------------------+------------------+
publicKeyBytes :: Int
publicKeyBytes = 1568

-- | The size of the secret key in bytes
--
-- +--------------------------------+------------------+
-- | Parameter set                  | Key size (bytes) |
-- +================================+==================+
-- | ML-KEM-512                     | 1632             |
-- +--------------------------------+------------------+
-- | ML-KEM-768                     | 2400             |
-- +--------------------------------+------------------+
-- | __ML-KEM-1024 (configured)__   | __3168__         |
-- +--------------------------------+------------------+
secretKeyBytes :: Int
secretKeyBytes = 3168

-- | The size of the ciphertext in bytes
--
-- +------------------------------+--------------------+
-- | Parameter set                | Text size (bytes)  |
-- +==============================+====================+
-- | ML-KEM-512                   | 768                |
-- +------------------------------+--------------------+
-- | ML-KEM-768                   | 1088               |
-- +------------------------------+--------------------+
-- | __ML-KEM-1024 (configured)__ | __1568__           |
-- +------------------------------+--------------------+
ciphertextBytes :: Int
ciphertextBytes = 1568

#elif MLK_HS_PARAM == 512

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand"
  mlkem_keypair_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_enc_derand"
  mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_dec"
  mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- | The size of the public key in bytes
--
-- +------------------------------+------------------+
-- | Parameter set                | Key size (bytes) |
-- +==============================+==================+
-- | __ML-KEM-512 (configured)__  | __800__          |
-- +------------------------------+------------------+
-- | ML-KEM-768                   | 1184             |
-- +------------------------------+------------------+
-- | ML-KEM-1024                  | 1568             |
-- +------------------------------+------------------+
publicKeyBytes :: Int
publicKeyBytes = 800

-- | The size of the secret key in bytes
--
-- +------------------------------+------------------+
-- | Parameter set                | Key size (bytes) |
-- +==============================+==================+
-- | __ML-KEM-512 (configured)__  | __1632__         |
-- +------------------------------+------------------+
-- | ML-KEM-768                   | 2400             |
-- +------------------------------+------------------+
-- | ML-KEM-1024                  | 3168             |
-- +------------------------------+------------------+
secretKeyBytes :: Int
secretKeyBytes = 1632

-- | The size of the ciphertext in bytes
--
-- +------------------------------+--------------------+
-- | Parameter set                | Text size (bytes)  |
-- +==============================+====================+
-- | __ML-KEM-512 (configured)__  | __768__            |
-- +------------------------------+--------------------+
-- | ML-KEM-768                   | 1088               |
-- +------------------------------+--------------------+
-- | ML-KEM-1024                  | 1568               |
-- +------------------------------+--------------------+
ciphertextBytes :: Int
ciphertextBytes = 768

#else

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand"
  mlkem_keypair_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_enc_derand"
  mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_dec"
  mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- | The size of the public key in bytes
--
-- +--------------------------------------+------------------+
-- | Parameter set                        | Key size (bytes) |
-- +======================================+==================+
-- | ML-KEM-512                           | 800              |
-- +--------------------------------------+------------------+
-- | __ML-KEM-768 (default, configured)__ | __1184__         |
-- +--------------------------------------+------------------+
-- | ML-KEM-1024                          | 1568             |
-- +--------------------------------------+------------------+
publicKeyBytes :: Int
publicKeyBytes = 1184

-- | The size of the secret key in bytes
--
-- +--------------------------------------+------------------+
-- | Parameter set                        | Key size (bytes) |
-- +======================================+==================+
-- | ML-KEM-512                           | 1632             |
-- +--------------------------------------+------------------+
-- | __ML-KEM-768 (default, configured)__ | __2400__         |
-- +--------------------------------------+------------------+
-- | ML-KEM-1024                          | 3168             |
-- +--------------------------------------+------------------+
secretKeyBytes :: Int
secretKeyBytes = 2400

-- | The size of the ciphertext in bytes
--
-- +--------------------------------------+--------------------+
-- | Parameter set                        | Text size (bytes)  |
-- +======================================+====================+
-- | ML-KEM-512                           | 768                |
-- +--------------------------------------+--------------------+
-- | __ML-KEM-768 (default, configured)__ | __1088__           |
-- +--------------------------------------+--------------------+
-- | ML-KEM-1024                          | 1568               |
-- +--------------------------------------+--------------------+
ciphertextBytes :: Int
ciphertextBytes = 1088

#endif

-- | The size of the shared secret. 32 bytes across all parameter sets.
sharedSecretBytes :: Int
sharedSecretBytes = 32

-- | Amount of entropy used as input for encapsulation. 32 bytes across all parameter sets.
encapsulationSeedBytes :: Int
encapsulationSeedBytes = 32

-- | Amount of entropy used as input for key pair generation. 64 bytes across all parameter sets.
keygenSeedBytes :: Int
keygenSeedBytes = 64

errorCodeInvalidPublicKey :: CInt
errorCodeInvalidPublicKey = -4

errorCodeInvalidSecretKey :: CInt
errorCodeInvalidSecretKey = -5

-- | Possible errors that can be returned by an ML-KEM operation
data CryptoError
  = -- | Public key validation failed (FIPS-203 section 7.2, "modulus check")
    PublicKeyValidationFailed
  | -- | Secret key validation failed (FIPS-203 section 7.3, "hash check")
    SecretKeyValidationFailed
  | -- | Invalid public key size. The correct size for the configured parameter set would be 'publicKeyBytes'.
    InvalidPublicKeySize
  | -- | Invalid encapsulation seed size. The standard size across all parameter sets is 32 bytes.
    InvalidEncapsulationSeedSize
  | -- | Invalid keygen seed size. The standard size across all parameter sets is 64 bytes.
    InvalidKeygenSeedSize
  | -- | Invalid secret key size. The correct size for the configured parameter set would be 'secretKeyBytes'.
    InvalidSecretKeySize
  | -- | Invalid ciphertext size. The correct size for the configured parameter set would be 'ciphertextBytes'.
    InvalidCiphertextSize
  | -- | ML-KEM operation returned an unexpected exit status
    UnexpectedStatus CInt
  deriving (Show)

instance Exception CryptoError

newtype PublicKey = PublicKey Bytes
  deriving newtype
    ( ByteArrayAccess.ByteArrayAccess
    , ByteArrayAccess.ByteArray
    , Eq
    , Monoid
    , Ord
    , Semigroup
    , Show
    )

newtype SecretKey = SecretKey ScrubbedBytes
  deriving newtype
    ( ByteArrayAccess.ByteArrayAccess
    , ByteArrayAccess.ByteArray
    , Eq
    , Monoid
    , Ord
    , Semigroup
    , Show
    )

-- | Ciphertext generated after encapsulation
newtype Ciphertext = Ciphertext Bytes
  deriving newtype
    ( ByteArrayAccess.ByteArrayAccess
    , ByteArrayAccess.ByteArray
    , Eq
    , Monoid
    , Ord
    , Semigroup
    , Show
    )

-- | Shared secret derived after encapsulation and decapsulation
newtype SharedSecret = SharedSecret ScrubbedBytes
  deriving newtype
    ( ByteArrayAccess.ByteArrayAccess
    , ByteArrayAccess.ByteArray
    , Eq
    , Monoid
    , Ord
    , Semigroup
    , Show
    )

-- | Generate an MK-KEM public-secret key pair
keyPair
  :: ByteArrayAccess seed
  => seed
  -- ^ 64 (or 'keygenSeedBytes') bytes of entropy
  -> Either CryptoError (PublicKey, SecretKey)
keyPair seed = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length seed == keygenSeedBytes) $ throwIO InvalidKeygenSeedSize
  (secretKey, publicKey) <- allocRet publicKeyBytes $ \pkPtr ->
    alloc secretKeyBytes $ \skPtr ->
      withByteArray seed $ \seedPtr -> do
        res <- mlkem_keypair_derand (castPtr pkPtr) (castPtr skPtr) (castPtr seedPtr)
        -- We should not expect any errors here
        unless (res == 0) $ throwIO $ UnexpectedStatus res
  pure (publicKey, secretKey)

-- | Using public key and some entropy, derive a shared secret and ciphertext
encaps
  :: ByteArrayAccess seed
  => PublicKey
  -- ^ ML-KEM public key
  -> seed
  -- ^ 32 (or 'encapsulationSeedBytes') bytes of entropy
  -> Either CryptoError (Ciphertext, SharedSecret)
encaps publicKey seed = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length publicKey == publicKeyBytes) $ throwIO InvalidPublicKeySize
  unless (ByteArrayAccess.length seed == encapsulationSeedBytes) $ throwIO InvalidEncapsulationSeedSize
  (sharedSecret, ciphertext) <- allocRet ciphertextBytes $ \ctPtr ->
    alloc sharedSecretBytes $ \ssPtr ->
      withByteArray publicKey $ \pkPtr ->
        withByteArray seed $ \seedPtr -> do
          res <- mlkem_enc_derand (castPtr ctPtr) (castPtr ssPtr) (castPtr pkPtr) (castPtr seedPtr)
          when (res == errorCodeInvalidPublicKey) $ throwIO PublicKeyValidationFailed
          unless (res == 0) $ throwIO $ UnexpectedStatus res
  pure (ciphertext, sharedSecret)

-- | Using secret key and ciphertext, derive a shared secret
decaps
  :: Ciphertext
  -> SecretKey
  -> Either CryptoError SharedSecret
decaps ciphertext secretKey = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length ciphertext == ciphertextBytes) $ throwIO InvalidCiphertextSize
  unless (ByteArrayAccess.length secretKey == secretKeyBytes) $ throwIO InvalidSecretKeySize
  alloc sharedSecretBytes $ \ssPtr ->
    withByteArray ciphertext $ \ctPtr ->
      withByteArray secretKey $ \skPtr -> do
        res <- mlkem_dec (castPtr ssPtr) (castPtr ctPtr) (castPtr skPtr)
        when (res == errorCodeInvalidSecretKey) $ throwIO SecretKeyValidationFailed
        unless (res == 0) $ throwIO $ UnexpectedStatus res
