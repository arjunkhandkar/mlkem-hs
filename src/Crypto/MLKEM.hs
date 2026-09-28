{- |
Module: Crypto.MLKEM 
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

Haskell bindings for ML-KEM primitives from mlkem-native
-}
module Crypto.MLKEM
  ( keyPair
  , encaps
  , decaps
  ) where

import Control.Monad (unless)
import Data.ByteArray (ByteArrayAccess, Bytes, ScrubbedBytes, alloc, allocRet, withByteArray)
import qualified Data.ByteArray as ByteArrayAccess
import Foreign (Ptr, Word8, castPtr)
import Foreign.C (CInt (CInt))

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
newtype Secret = Secret ScrubbedBytes
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
  -> IO (PublicKey, SecretKey)
keyPair seed = do
  unless (ByteArrayAccess.length seed == keyGenSeedBytes) $ error "Incorrect seed size"
  (secretKey, publicKey) <- allocRet publicKeyBytes $ \pkPtr ->
    alloc secretKeyBytes $ \skPtr ->
      withByteArray seed $ \seedPtr -> do
        res <- mlkem_keypair_derand (castPtr pkPtr) (castPtr skPtr) (castPtr seedPtr)
        unless (res == 0) $ error "Keypair gen failed"
  pure (publicKey, secretKey)

-- | ML-KEM encapsulation: Using public key and some entropy, derive a shared secret and ciphertext
encaps
  :: ByteArrayAccess seed
  => PublicKey
  -- ^ ML-KEM public key
  -> seed
  -- ^ 32 bytes of entropy
  -> IO (Ciphertext, Secret)
encaps publicKey seed = do
  unless (ByteArrayAccess.length publicKey == publicKeyBytes) $ error "Invalid public key size"
  unless (ByteArrayAccess.length seed == encapsulationSeedBytes) $ error "Invalid encapsulation seed size"
  (sharedSecret, ciphertext) <- allocRet cipherTextBytes $ \ctPtr ->
    alloc sharedSecretBytes $ \ssPtr ->
      withByteArray publicKey $ \pkPtr ->
        withByteArray seed $ \seedPtr -> do
          res <- mlkem_enc_derand (castPtr ctPtr) (castPtr ssPtr) (castPtr pkPtr) (castPtr seedPtr)
          unless (res == 0) $ error "Encaps error"
  pure (ciphertext, sharedSecret)

-- | ML-KEM decapsulation: Using secret key and ciphertext, derive a shared secret
decaps
  :: Ciphertext
  -> SecretKey
  -> IO Secret
decaps ciphertext secretKey = do
  unless (ByteArrayAccess.length ciphertext == cipherTextBytes) $ error "Invalid ciphertext length"
  unless (ByteArrayAccess.length secretKey == secretKeyBytes) $ error "Invalid secret key bytes"
  alloc sharedSecretBytes $ \ssPtr ->
    withByteArray ciphertext $ \ctPtr ->
      withByteArray secretKey $ \skPtr -> do
        res <- mlkem_dec (castPtr ssPtr) (castPtr ctPtr) (castPtr skPtr)
        unless (res == 0) $ error "Decaps error"
