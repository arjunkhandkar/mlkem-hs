{- |
Module: Crypto.MLKEM
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

Haskell bindings for ML-KEM primitives from mlkem-native
-}
module Crypto.MLKEM
  ( -- * Key pair generation
    keyPair

    -- * Encapsulation and decapsulation
  , encaps
  , decaps

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

publicKeyBytes, secretKeyBytes, cipherTextBytes :: Int
publicKeyBytes = 1568 
secretKeyBytes = 3168 
cipherTextBytes = 1568

#elif MLK_HS_PARAM == 512

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand"
  mlkem_keypair_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_enc_derand"
  mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_dec"
  mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

publicKeyBytes, secretKeyBytes, cipherTextBytes :: Int
publicKeyBytes = 800 
secretKeyBytes = 1632 
cipherTextBytes = 768

#else

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand"
  mlkem_keypair_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_enc_derand"
  mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_dec"
  mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

publicKeyBytes, secretKeyBytes, cipherTextBytes :: Int
publicKeyBytes = 1184
secretKeyBytes = 2400
cipherTextBytes = 1088

#endif

sharedSecretBytes :: Int
sharedSecretBytes = 32

encapsulationSeedBytes :: Int
encapsulationSeedBytes = 32

keyGenSeedBytes :: Int
keyGenSeedBytes = 64

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
  | -- | Invalid public key size.
    --
    -- Public key sizes for the ML-KEM parameter sets are as follows:
    --
    -- +---------------+------------+
    -- | Parameter set | Key size   |
    -- +===============+============+
    -- | ML-KEM-512    | 800 bytes  |
    -- +---------------+------------+
    -- | ML-KEM-768    | 1184 bytes |
    -- +---------------+------------+
    -- | ML-KEM-1024   | 1568 bytes |
    -- +---------------+------------+
    InvalidPublicKeySize
  | -- | Invalid encapsulation seed size. The standard size across all parameter sets is 32 bytes.
    InvalidEncapsulationSeedSize
  | -- | Invalid keygen seed size. The standard size across all parameter sets is 64 bytes.
    InvalidKeygenSeedSize
  | -- | Invalid secret key size.
    --
    -- Secret key sizes for the ML-KEM parameter sets are as follows:
    --
    -- +---------------+------------+
    -- | Parameter set | Key size   |
    -- +===============+============+
    -- | ML-KEM-512    | 1632 bytes |
    -- +---------------+------------+
    -- | ML-KEM-768    | 2400 bytes |
    -- +---------------+------------+
    -- | ML-KEM-1024   | 3168 bytes |
    -- +---------------+------------+
    InvalidSecretKeySize
  | -- | Invalid ciphertext size.
    --
    -- Ciphertext sizes for the ML-KEM parameter sets are as follows:
    --
    -- +---------------+------------+
    -- | Parameter set | Text size  |
    -- +===============+============+
    -- | ML-KEM-512    | 768 bytes  |
    -- +---------------+------------+
    -- | ML-KEM-768    | 1088 bytes |
    -- +---------------+------------+
    -- | ML-KEM-1024   | 1568 bytes |
    -- +---------------+------------+
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
  -- ^ 64 bytes of entropy
  -> Either CryptoError (PublicKey, SecretKey)
keyPair seed = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length seed == keyGenSeedBytes) $ throwIO InvalidKeygenSeedSize
  (secretKey, publicKey) <- allocRet publicKeyBytes $ \pkPtr ->
    alloc secretKeyBytes $ \skPtr ->
      withByteArray seed $ \seedPtr -> do
        res <- mlkem_keypair_derand (castPtr pkPtr) (castPtr skPtr) (castPtr seedPtr)
        -- We should not expect any errors here
        unless (res == 0) $ throwIO $ UnexpectedStatus res
  pure (publicKey, secretKey)

-- | ML-KEM encapsulation: Using public key and some entropy, derive a shared secret and ciphertext
encaps
  :: ByteArrayAccess seed
  => PublicKey
  -- ^ ML-KEM public key
  -> seed
  -- ^ 32 bytes of entropy
  -> Either CryptoError (Ciphertext, SharedSecret)
encaps publicKey seed = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length publicKey == publicKeyBytes) $ throwIO InvalidPublicKeySize
  unless (ByteArrayAccess.length seed == encapsulationSeedBytes) $ throwIO InvalidEncapsulationSeedSize
  (sharedSecret, ciphertext) <- allocRet cipherTextBytes $ \ctPtr ->
    alloc sharedSecretBytes $ \ssPtr ->
      withByteArray publicKey $ \pkPtr ->
        withByteArray seed $ \seedPtr -> do
          res <- mlkem_enc_derand (castPtr ctPtr) (castPtr ssPtr) (castPtr pkPtr) (castPtr seedPtr)
          when (res == errorCodeInvalidPublicKey) $ throwIO PublicKeyValidationFailed
          unless (res == 0) $ throwIO $ UnexpectedStatus res
  pure (ciphertext, sharedSecret)

-- | ML-KEM decapsulation: Using secret key and ciphertext, derive a shared secret
decaps
  :: Ciphertext
  -> SecretKey
  -> Either CryptoError SharedSecret
decaps ciphertext secretKey = unsafePerformIO $ try $ do
  unless (ByteArrayAccess.length ciphertext == cipherTextBytes) $ throwIO InvalidCiphertextSize
  unless (ByteArrayAccess.length secretKey == secretKeyBytes) $ throwIO InvalidSecretKeySize
  alloc sharedSecretBytes $ \ssPtr ->
    withByteArray ciphertext $ \ctPtr ->
      withByteArray secretKey $ \skPtr -> do
        res <- mlkem_dec (castPtr ssPtr) (castPtr ctPtr) (castPtr skPtr)
        when (res == errorCodeInvalidSecretKey) $ throwIO SecretKeyValidationFailed
        unless (res == 0) $ throwIO $ UnexpectedStatus res
