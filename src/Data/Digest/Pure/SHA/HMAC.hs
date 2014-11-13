-- |Standard HMAC functions for the SHA suite of hash functions.
module Data.Digest.Pure.SHA.HMAC(
         hmacSha1
       , hmacSha224
       , hmacSha256
       , hmacSha384
       , hmacSha512
       )
 where

import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Word

-- | Compute an HMAC using SHA-1.
hmacSha1
  :: ByteString  -- ^ secret key
  -> ByteString  -- ^ message
  -> ByteString  -- ^ SHA-1 MAC
hmacSha1 = hmac sha1 64

-- | Compute an HMAC using SHA-224.
hmacSha224
  :: ByteString  -- ^ secret key
  -> ByteString  -- ^ message
  -> ByteString  -- ^ SHA-224 MAC
hmacSha224 = hmac sha224 64

-- | Compute an HMAC using SHA-256.
hmacSha256
  :: ByteString  -- ^ secret key
  -> ByteString  -- ^ message
  -> ByteString  -- ^ SHA-256 MAC
hmacSha256 = hmac sha256 64

-- | Compute an HMAC using SHA-384.
hmacSha384
  :: ByteString  -- ^ secret key
  -> ByteString  -- ^ message
  -> ByteString     -- ^ SHA-384 MAC
hmacSha384 = hmac sha384 128

-- | Compute an HMAC using SHA-512.
hmacSha512
  :: ByteString  -- ^ secret key
  -> ByteString  -- ^ message
  -> ByteString     -- ^ SHA-512 MAC
hmacSha512 = hmac sha512 128

-- --------------------------------------------------------------------------

-- |Compute the HMAC function for the given hash function and block size.
hmac :: (ByteString -> ByteString) ->
        Int -> ByteString -> ByteString ->
        ByteString
hmac f bl k m = f (BS.append opad (f (BS.append ipad m)))
 where
  opad = BS.map (xor ov) k'
  ipad = BS.map (xor iv) k'
  ov = 0x5c :: Word8
  iv = 0x36 :: Word8

  k' = BS.append kt pad
   where
    kt  = if kn > bn then f k else k
    pad = BS.replicate (bn - ktn) 0
    kn  = fromIntegral (BS.length k)
    ktn = fromIntegral (BS.length kt)
    bn  = fromIntegral bl


