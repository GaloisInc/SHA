module Data.Digest.Pure.SHA.Padding
 where

import           Control.Monad
import           Data.Binary.Put
import qualified Data.ByteString.Lazy as L
import           Data.Word

-- |Generate the appropriate pad for a SHA algorithm, given 'a', 'b', the number
-- of bytes hashed in bytes, and the length of the output length field in bytes.
-- For SHA1, SHA224, and SHA256, 'a' should be 448, 'b' should be 512, and the
-- output length field size should be 8. For SHA384 and SHA512, 'a' should be
-- 896, 'b' should be 1024, and the output length field size should be 16.
generatePad :: Word64 -> Word64 -> Word64 -> Word64 -> L.ByteString
generatePad a b inputNumBytes lengthFieldLength =
  runPut $ do putWord8 0x80
              replicateM_ nZeroBytes (putWord8 0)
              when (lengthFieldLength == 16) $ putWord64be 0
              putWord64be inputNumBits
 where
  inputNumBits = inputNumBytes * 8
  k            = calc_k a b inputNumBits
  -- INVARIANT: k is necessarily > 0, and (k + 1) is a multiple of 8.
  kBytes       = (k + 1) `div` 8
  nZeroBytes   = fromIntegral (kBytes - 1)

-- |Given a, b, and l, calculate the smallest k such that (l + 1 + k) mod b = a.
calc_k :: Word64 -> Word64 -> Word64 -> Word64
calc_k a b l =
  if r <= -1
    then fromIntegral r + b
    else fromIntegral r
 where
  r = toInteger a - toInteger l `mod` toInteger b - 1


