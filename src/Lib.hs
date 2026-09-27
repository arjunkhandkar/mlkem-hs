{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CPP #-}

module Lib
    ( keyPair
    , encaps
    , decaps
    ) where

import Foreign (Ptr, Word8, castPtr)
import Foreign.C (CInt(CInt))
import Control.Monad (unless)
import Data.ByteArray (ByteArrayAccess, Bytes, ScrubbedBytes, alloc, allocRet, withByteArray)
import qualified Data.ByteArray as ByteArrayAccess

#if MLK_HS_PARAM == 1024

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_keypair_derand"
  c_mlkem_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_enc_derand"
  c_mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM1024_dec"
  c_mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

publicKeyBytes, secretKeyBytes, cipherTextBytes :: Int
publicKeyBytes = 1568 
secretKeyBytes = 3168 
cipherTextBytes = 1568

#elif MLK_HS_PARAM == 512

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand"
  c_mlkem_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_enc_derand"
  c_mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM512_dec"
  c_mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

publicKeyBytes, secretKeyBytes, cipherTextBytes :: Int
publicKeyBytes = 800 
secretKeyBytes = 1632 
cipherTextBytes = 768

#else

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand"
  c_mlkem_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_enc_derand"
  c_mlkem_enc_derand :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall "PQCP_MLKEM_NATIVE_MLKEM768_dec"
  c_mlkem_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

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

keyPair :: ByteArrayAccess seed => seed -> IO (Bytes, ScrubbedBytes)
keyPair seed = do
  unless (ByteArrayAccess.length seed == keyGenSeedBytes) $ error "Incorrect seed size"
  (secretKey, publicKey) <- allocRet publicKeyBytes $ \pkPtr ->
    alloc secretKeyBytes $ \skPtr ->
      withByteArray seed $ \seedPtr -> do
        res <- c_mlkem_keypair (castPtr pkPtr) (castPtr skPtr) (castPtr seedPtr)
        unless (res == 0) $ error "Keypair gen failed"
  pure (publicKey, secretKey)

encaps
  :: (ByteArrayAccess publicKey, ByteArrayAccess seed)
  => publicKey
  -> seed
  -> IO (Bytes, ScrubbedBytes)
encaps publicKey seed = do
  unless (ByteArrayAccess.length publicKey == publicKeyBytes) $ error "Invalid public key size"
  unless (ByteArrayAccess.length seed == encapsulationSeedBytes) $ error "Invalid encapsulation seed size"
  (sharedSecret, ciphertext) <- allocRet cipherTextBytes $ \ctPtr ->
    alloc sharedSecretBytes $ \ssPtr ->
      withByteArray publicKey $ \pkPtr ->
        withByteArray seed $ \seedPtr -> do
          res <- c_mlkem_enc_derand (castPtr ctPtr) (castPtr ssPtr) (castPtr pkPtr) (castPtr seedPtr)
          unless (res == 0) $ error "Encaps error"
  pure (ciphertext, sharedSecret)

decaps
  :: (ByteArrayAccess ciphertext, ByteArrayAccess secretKey)
  => ciphertext
  -> secretKey
  -> IO ScrubbedBytes
decaps ciphertext secretKey = do
  unless (ByteArrayAccess.length ciphertext == cipherTextBytes) $ error "Invalid ciphertext length"
  unless (ByteArrayAccess.length secretKey == secretKeyBytes) $ error "Invalid secret key bytes"
  alloc sharedSecretBytes $ \ssPtr ->
    withByteArray ciphertext $ \ctPtr ->
      withByteArray secretKey $ \skPtr -> do
        res <- c_mlkem_dec (castPtr ssPtr) (castPtr ctPtr) (castPtr skPtr)
        unless (res == 0) $ error "Decaps error"
