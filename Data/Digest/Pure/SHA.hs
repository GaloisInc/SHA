-- |Pure implementations of the SHA suite of hash functions. The implementation
-- is basically an unoptimized translation of FIPS 180-2 into Haskell. If you're
-- looking for performance, you probably won't find it here.
module Data.Digest.Pure.SHA
       ( Digest
       , sha1
       , sha224
       , sha256
       , sha384
       , sha512
       , showDigest
       , integerDigest
       , bytestringDigest
#ifdef SHA_TEST
       , toBigEndianBS, fromBigEndianBS
       , find_k
       , padSHA1, padSHA512
#endif
       )
 where

import qualified Data.Array as Arr
import Data.Array.Unboxed
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Char
import Data.Int
import Data.Word

-- | An abstract datatype for digests.
newtype Digest = Digest ByteString deriving (Eq,Ord)

instance Show Digest where
  show = showDigest

-- --------------------------------------------------------------------------
--
-- CONSTANT ARRAYS
--
-- --------------------------------------------------------------------------

-- The following arrays represent K_i.

sha1_k :: UArray Int Word32
sha1_k = listArray (0, 79)  [
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999  
  , 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999  
  , 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999  
  , 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
  , 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
  , 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
  , 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
  , 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
  , 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
  , 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
  , 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
  , 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
  , 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
  , 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
  , 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
  , 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
  ]

sha256_k :: UArray Int Word32
sha256_k = listArray (0, 63) [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b
  , 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01
  , 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7
  , 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
  , 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152
  , 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147
  , 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc
  , 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85 
  , 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819
  , 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08
  , 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f
  , 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
  , 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

sha512_k :: UArray Int Word64
sha512_k = listArray (0, 79) [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f
  , 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019
  , 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242
  , 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
  , 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235
  , 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
  , 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275
  , 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
  , 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f
  , 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
  , 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc
  , 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
  , 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6
  , 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001
  , 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218
  , 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
  , 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99
  , 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
  , 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc
  , 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
  , 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915
  , 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207
  , 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba
  , 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
  , 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc
  , 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
  , 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  ]

-- --------------------------------------------------------------------------
--
-- State Definitions and Initial States
--
-- --------------------------------------------------------------------------

data SHA1State = SHA1S !Word32 !Word32 !Word32 !Word32 !Word32

initialSHA1State :: SHA1State
initialSHA1State = SHA1S 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0

data SHA256State = SHA256S !Word32 !Word32 !Word32 !Word32
                           !Word32 !Word32 !Word32 !Word32

initialSHA224State :: SHA256State
initialSHA224State = SHA256S 0xc1059ed8 0x367cd507 0x3070dd17 0xf70e5939
                             0xffc00b31 0x68581511 0x64f98fa7 0xbefa4fa4

initialSHA256State :: SHA256State
initialSHA256State = SHA256S 0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
                             0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19

data SHA512State = SHA512S !Word64 !Word64 !Word64 !Word64
                           !Word64 !Word64 !Word64 !Word64

initialSHA384State :: SHA512State
initialSHA384State = SHA512S 0xcbbb9d5dc1059ed8 0x629a292a367cd507
                             0x9159015a3070dd17 0x152fecd8f70e5939
                             0x67332667ffc00b31 0x8eb44a8768581511
                             0xdb0c2e0d64f98fa7 0x47b5481dbefa4fa4

initialSHA512State :: SHA512State
initialSHA512State = SHA512S 0x6a09e667f3bcc908 0xbb67ae8584caa73b
                             0x3c6ef372fe94f82b 0xa54ff53a5f1d36f1
                             0x510e527fade682d1 0x9b05688c2b3e6c1f
                             0x1f83d9abfb41bd6b 0x5be0cd19137e2179

-- --------------------------------------------------------------------------
--
-- Synthesize of states to ByteStrings
--
-- --------------------------------------------------------------------------

synthesizeSHA1 :: SHA1State -> Put
synthesizeSHA1 (SHA1S a b c d e) = do
  putWord32be a
  putWord32be b
  putWord32be c
  putWord32be d
  putWord32be e

synthesizeSHA224 :: SHA256State -> Put
synthesizeSHA224 (SHA256S a b c d e f g _) = do
  putWord32be a
  putWord32be b
  putWord32be c
  putWord32be d
  putWord32be e
  putWord32be f
  putWord32be g

synthesizeSHA256 :: SHA256State -> Put
synthesizeSHA256 (SHA256S a b c d e f g h) = do
  putWord32be a
  putWord32be b
  putWord32be c
  putWord32be d
  putWord32be e
  putWord32be f
  putWord32be g
  putWord32be h

synthesizeSHA384 :: SHA512State -> Put
synthesizeSHA384 (SHA512S a b c d e f _ _) = do
  putWord64be a
  putWord64be b
  putWord64be c
  putWord64be d
  putWord64be e
  putWord64be f

synthesizeSHA512 :: SHA512State -> Put
synthesizeSHA512 (SHA512S a b c d e f g h) = do
  putWord64be a
  putWord64be b
  putWord64be c
  putWord64be d
  putWord64be e
  putWord64be f
  putWord64be g
  putWord64be h

-- --------------------------------------------------------------------------
--
-- Padding
--
-- --------------------------------------------------------------------------

padSHA1 :: ByteString -> ByteString
padSHA1 = generic_pad 448 512 64

padSHA512 :: ByteString -> ByteString
padSHA512 = generic_pad 896 1024 128

generic_pad :: Word64 -> Word64 -> Int -> ByteString -> ByteString
generic_pad a b lSize bs = BS.concat [bs, pad_bytes, pad_length]
 where
  l = fromIntegral $ BS.length bs * 8
  k = find_k a b l
  -- INVARIANT: k is necessarily > 0, and (k + 1) is a multiple of 8.
  k_bytes = (k + 1) `div` 8
  pad_bytes = BS.pack $ [0x80] ++ (take (fromIntegral $ k_bytes - 1) [0,0 ..])
  pad_length = toBigEndianBS lSize l

-- Given a, b, and l, find a k such that (l + 1 + k) mod b = a. This is an
-- astoundingly brain-dead implementation.
find_k :: Word64 -> Word64 -> Word64 -> Word64
find_k a b l = try_k 7
 where
  try_k k | (l + 1 + k) `mod` b == a = k
          | otherwise                = try_k (k + 8)

toBigEndianBS :: (Integral a, Bits a) => Int -> a -> ByteString
toBigEndianBS s val = BS.pack $ map getBits [s - 8, s - 16 .. 0]
 where 
   getBits x = fromIntegral $ (val `shiftR` x) .&. 0xFF

#ifdef SHA_TEST
fromBigEndianBS :: (Integral a, Bits a) => ByteString -> a
fromBigEndianBS bs = 
  BS.foldl (\ acc x -> (acc `shiftL` 8) + (fromIntegral x)) 0 bs
#endif

-- --------------------------------------------------------------------------
--
-- SHA Functions
--
-- --------------------------------------------------------------------------

sha1_f :: Arr.Array Int (Word32 -> Word32 -> Word32 -> Word32)
sha1_f = Arr.listArray (0,79) [
        ch,     ch,     ch,     ch,     ch
  ,     ch,     ch,     ch,     ch,     ch
  ,     ch,     ch,     ch,     ch,     ch
  ,     ch,     ch,     ch,     ch,     ch
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  ,    maj,    maj,    maj,    maj,    maj
  ,    maj,    maj,    maj,    maj,    maj
  ,    maj,    maj,    maj,    maj,    maj
  ,    maj,    maj,    maj,    maj,    maj
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  , parity, parity, parity, parity, parity
  ]

ch :: Bits a => a -> a -> a -> a
ch x y z = (x .&. y) `xor` ((complement x) .&. z)

parity :: Bits a => a -> a -> a -> a
parity x y z = x `xor` y `xor` z

maj :: Bits a => a -> a -> a -> a
maj x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)

bsig256_0 :: Word32 -> Word32
bsig256_0 x = (rotate x (-2)) `xor` (rotate x (-13)) `xor` (rotate x (-22))

bsig256_1 :: Word32 -> Word32
bsig256_1 x = (rotate x (-6)) `xor` (rotate x (-11)) `xor` (rotate x (-25))

lsig256_0 :: Word32 -> Word32
lsig256_0 x = (rotate x (-7)) `xor` (rotate x (-18)) `xor` (shiftR x 3)

lsig256_1 :: Word32 -> Word32
lsig256_1 x = (rotate x (-17)) `xor` (rotate x (-19)) `xor` (shiftR x 10) 

bsig512_0 :: Word64 -> Word64
bsig512_0 x = (rotate x (-28)) `xor` (rotate x (-34)) `xor` (rotate x (-39))

bsig512_1 :: Word64 -> Word64
bsig512_1 x = (rotate x (-14)) `xor` (rotate x (-18)) `xor` (rotate x (-41))

lsig512_0 :: Word64 -> Word64
lsig512_0 x = (rotate x (-1)) `xor` (rotate x (-8)) `xor` (shiftR x 7)

lsig512_1 :: Word64 -> Word64
lsig512_1 x = (rotate x (-19)) `xor` (rotate x (-61)) `xor` (shiftR x 6)

-- --------------------------------------------------------------------------
--
-- Message Schedules
--
-- --------------------------------------------------------------------------

data SHA1Sched = SHA1Sched !Word32 !Word32 !Word32 !Word32 !Word32 --  0 -  4
                           !Word32 !Word32 !Word32 !Word32 !Word32 --  5 -  9
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 10 - 14
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 15 - 19
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 20 - 24
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 25 - 29
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 30 - 34
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 35 - 39
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 40 - 44
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 45 - 49
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 50 - 54
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 55 - 59
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 60 - 64
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 65 - 69
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 70 - 74
                           !Word32 !Word32 !Word32 !Word32 !Word32 -- 75 - 79

getSHA1Sched :: Get SHA1Sched
getSHA1Sched = do
  w00 <- getWord32be
  w01 <- getWord32be
  w02 <- getWord32be
  w03 <- getWord32be
  w04 <- getWord32be
  w05 <- getWord32be
  w06 <- getWord32be
  w07 <- getWord32be
  w08 <- getWord32be
  w09 <- getWord32be
  w10 <- getWord32be
  w11 <- getWord32be
  w12 <- getWord32be
  w13 <- getWord32be
  w14 <- getWord32be
  w15 <- getWord32be
  let w16 = rotate (w13 `xor` w08 `xor` w02 `xor` w00) 1
      w17 = rotate (w14 `xor` w09 `xor` w03 `xor` w01) 1
      w18 = rotate (w15 `xor` w10 `xor` w04 `xor` w02) 1
      w19 = rotate (w16 `xor` w11 `xor` w05 `xor` w03) 1
      w20 = rotate (w17 `xor` w12 `xor` w06 `xor` w04) 1
      w21 = rotate (w18 `xor` w13 `xor` w07 `xor` w05) 1
      w22 = rotate (w19 `xor` w14 `xor` w08 `xor` w06) 1
      w23 = rotate (w20 `xor` w15 `xor` w09 `xor` w07) 1
      w24 = rotate (w21 `xor` w16 `xor` w10 `xor` w08) 1
      w25 = rotate (w22 `xor` w17 `xor` w11 `xor` w09) 1
      w26 = rotate (w23 `xor` w18 `xor` w12 `xor` w10) 1
      w27 = rotate (w24 `xor` w19 `xor` w13 `xor` w11) 1
      w28 = rotate (w25 `xor` w20 `xor` w14 `xor` w12) 1
      w29 = rotate (w26 `xor` w21 `xor` w15 `xor` w13) 1
      w30 = rotate (w27 `xor` w22 `xor` w16 `xor` w14) 1
      w31 = rotate (w28 `xor` w23 `xor` w17 `xor` w15) 1
      w32 = rotate (w29 `xor` w24 `xor` w18 `xor` w16) 1
      w33 = rotate (w30 `xor` w25 `xor` w19 `xor` w17) 1
      w34 = rotate (w31 `xor` w26 `xor` w20 `xor` w18) 1
      w35 = rotate (w32 `xor` w27 `xor` w21 `xor` w19) 1
      w36 = rotate (w33 `xor` w28 `xor` w22 `xor` w20) 1
      w37 = rotate (w34 `xor` w29 `xor` w23 `xor` w21) 1
      w38 = rotate (w35 `xor` w30 `xor` w24 `xor` w22) 1
      w39 = rotate (w36 `xor` w31 `xor` w25 `xor` w23) 1
      w40 = rotate (w37 `xor` w32 `xor` w26 `xor` w24) 1
      w41 = rotate (w38 `xor` w33 `xor` w27 `xor` w25) 1
      w42 = rotate (w39 `xor` w34 `xor` w28 `xor` w26) 1
      w43 = rotate (w40 `xor` w35 `xor` w29 `xor` w27) 1
      w44 = rotate (w41 `xor` w36 `xor` w30 `xor` w28) 1
      w45 = rotate (w42 `xor` w37 `xor` w31 `xor` w29) 1
      w46 = rotate (w43 `xor` w38 `xor` w32 `xor` w30) 1
      w47 = rotate (w44 `xor` w39 `xor` w33 `xor` w31) 1
      w48 = rotate (w45 `xor` w40 `xor` w34 `xor` w32) 1
      w49 = rotate (w46 `xor` w41 `xor` w35 `xor` w33) 1
      w50 = rotate (w47 `xor` w42 `xor` w36 `xor` w34) 1
      w51 = rotate (w48 `xor` w43 `xor` w37 `xor` w35) 1
      w52 = rotate (w49 `xor` w44 `xor` w38 `xor` w36) 1
      w53 = rotate (w50 `xor` w45 `xor` w39 `xor` w37) 1
      w54 = rotate (w51 `xor` w46 `xor` w40 `xor` w38) 1
      w55 = rotate (w52 `xor` w47 `xor` w41 `xor` w39) 1
      w56 = rotate (w53 `xor` w48 `xor` w42 `xor` w40) 1
      w57 = rotate (w54 `xor` w49 `xor` w43 `xor` w41) 1
      w58 = rotate (w55 `xor` w50 `xor` w44 `xor` w42) 1
      w59 = rotate (w56 `xor` w51 `xor` w45 `xor` w43) 1
      w60 = rotate (w57 `xor` w52 `xor` w46 `xor` w44) 1
      w61 = rotate (w58 `xor` w53 `xor` w47 `xor` w45) 1
      w62 = rotate (w59 `xor` w54 `xor` w48 `xor` w46) 1
      w63 = rotate (w60 `xor` w55 `xor` w49 `xor` w47) 1
      w64 = rotate (w61 `xor` w56 `xor` w50 `xor` w48) 1
      w65 = rotate (w62 `xor` w57 `xor` w51 `xor` w49) 1
      w66 = rotate (w63 `xor` w58 `xor` w52 `xor` w50) 1
      w67 = rotate (w64 `xor` w59 `xor` w53 `xor` w51) 1
      w68 = rotate (w65 `xor` w60 `xor` w54 `xor` w52) 1
      w69 = rotate (w66 `xor` w61 `xor` w55 `xor` w53) 1
      w70 = rotate (w67 `xor` w62 `xor` w56 `xor` w54) 1
      w71 = rotate (w68 `xor` w63 `xor` w57 `xor` w55) 1
      w72 = rotate (w69 `xor` w64 `xor` w58 `xor` w56) 1
      w73 = rotate (w70 `xor` w65 `xor` w59 `xor` w57) 1
      w74 = rotate (w71 `xor` w66 `xor` w60 `xor` w58) 1
      w75 = rotate (w72 `xor` w67 `xor` w61 `xor` w59) 1
      w76 = rotate (w73 `xor` w68 `xor` w62 `xor` w60) 1
      w77 = rotate (w74 `xor` w69 `xor` w63 `xor` w61) 1
      w78 = rotate (w75 `xor` w70 `xor` w64 `xor` w62) 1
      w79 = rotate (w76 `xor` w71 `xor` w65 `xor` w63) 1
  return $ SHA1Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09
                     w10 w11 w12 w13 w14 w15 w16 w17 w18 w19
                     w20 w21 w22 w23 w24 w25 w26 w27 w28 w29
                     w30 w31 w32 w33 w34 w35 w36 w37 w38 w39
                     w40 w41 w42 w43 w44 w45 w46 w47 w48 w49
                     w50 w51 w52 w53 w54 w55 w56 w57 w58 w59
                     w60 w61 w62 w63 w64 w65 w66 w67 w68 w69
                     w70 w71 w72 w73 w74 w75 w76 w77 w78 w79

data SHA256Sched = SHA256Sched !Word32 !Word32 !Word32 !Word32 !Word32 -- 00-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 05-09
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 10-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 15-09
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 20-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 25-09
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 30-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 35-09
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 40-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 45-09
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 50-04
                               !Word32 !Word32 !Word32 !Word32 !Word32 -- 55-09
                               !Word32 !Word32 !Word32 !Word32         -- 60-63

getSHA256Sched :: Get SHA256Sched
getSHA256Sched = do
  w00 <- getWord32be
  w01 <- getWord32be
  w02 <- getWord32be
  w03 <- getWord32be
  w04 <- getWord32be
  w05 <- getWord32be
  w06 <- getWord32be
  w07 <- getWord32be
  w08 <- getWord32be
  w09 <- getWord32be
  w10 <- getWord32be
  w11 <- getWord32be
  w12 <- getWord32be
  w13 <- getWord32be
  w14 <- getWord32be
  w15 <- getWord32be
  let w16 = (lsig256_1 w14) + w09 + (lsig256_0 w01) + w00
      w17 = (lsig256_1 w15) + w10 + (lsig256_0 w02) + w01
      w18 = (lsig256_1 w16) + w11 + (lsig256_0 w03) + w02
      w19 = (lsig256_1 w17) + w12 + (lsig256_0 w04) + w03
      w20 = (lsig256_1 w18) + w13 + (lsig256_0 w05) + w04
      w21 = (lsig256_1 w19) + w14 + (lsig256_0 w06) + w05
      w22 = (lsig256_1 w20) + w15 + (lsig256_0 w07) + w06
      w23 = (lsig256_1 w21) + w16 + (lsig256_0 w08) + w07
      w24 = (lsig256_1 w22) + w17 + (lsig256_0 w09) + w08
      w25 = (lsig256_1 w23) + w18 + (lsig256_0 w10) + w09
      w26 = (lsig256_1 w24) + w19 + (lsig256_0 w11) + w10
      w27 = (lsig256_1 w25) + w20 + (lsig256_0 w12) + w11
      w28 = (lsig256_1 w26) + w21 + (lsig256_0 w13) + w12
      w29 = (lsig256_1 w27) + w22 + (lsig256_0 w14) + w13
      w30 = (lsig256_1 w28) + w23 + (lsig256_0 w15) + w14
      w31 = (lsig256_1 w29) + w24 + (lsig256_0 w16) + w15
      w32 = (lsig256_1 w30) + w25 + (lsig256_0 w17) + w16
      w33 = (lsig256_1 w31) + w26 + (lsig256_0 w18) + w17
      w34 = (lsig256_1 w32) + w27 + (lsig256_0 w19) + w18
      w35 = (lsig256_1 w33) + w28 + (lsig256_0 w20) + w19
      w36 = (lsig256_1 w34) + w29 + (lsig256_0 w21) + w20
      w37 = (lsig256_1 w35) + w30 + (lsig256_0 w22) + w21
      w38 = (lsig256_1 w36) + w31 + (lsig256_0 w23) + w22
      w39 = (lsig256_1 w37) + w32 + (lsig256_0 w24) + w23
      w40 = (lsig256_1 w38) + w33 + (lsig256_0 w25) + w24
      w41 = (lsig256_1 w39) + w34 + (lsig256_0 w26) + w25
      w42 = (lsig256_1 w40) + w35 + (lsig256_0 w27) + w26
      w43 = (lsig256_1 w41) + w36 + (lsig256_0 w28) + w27
      w44 = (lsig256_1 w42) + w37 + (lsig256_0 w29) + w28
      w45 = (lsig256_1 w43) + w38 + (lsig256_0 w30) + w29
      w46 = (lsig256_1 w44) + w39 + (lsig256_0 w31) + w30
      w47 = (lsig256_1 w45) + w40 + (lsig256_0 w32) + w31
      w48 = (lsig256_1 w46) + w41 + (lsig256_0 w33) + w32
      w49 = (lsig256_1 w47) + w42 + (lsig256_0 w34) + w33
      w50 = (lsig256_1 w48) + w43 + (lsig256_0 w35) + w34
      w51 = (lsig256_1 w49) + w44 + (lsig256_0 w36) + w35
      w52 = (lsig256_1 w50) + w45 + (lsig256_0 w37) + w36
      w53 = (lsig256_1 w51) + w46 + (lsig256_0 w38) + w37
      w54 = (lsig256_1 w52) + w47 + (lsig256_0 w39) + w38
      w55 = (lsig256_1 w53) + w48 + (lsig256_0 w40) + w39
      w56 = (lsig256_1 w54) + w49 + (lsig256_0 w41) + w40
      w57 = (lsig256_1 w55) + w50 + (lsig256_0 w42) + w41
      w58 = (lsig256_1 w56) + w51 + (lsig256_0 w43) + w42
      w59 = (lsig256_1 w57) + w52 + (lsig256_0 w44) + w43
      w60 = (lsig256_1 w58) + w53 + (lsig256_0 w45) + w44
      w61 = (lsig256_1 w59) + w54 + (lsig256_0 w46) + w45
      w62 = (lsig256_1 w60) + w55 + (lsig256_0 w47) + w46
      w63 = (lsig256_1 w61) + w56 + (lsig256_0 w48) + w47
  return $ SHA256Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09
                       w10 w11 w12 w13 w14 w15 w16 w17 w18 w19
                       w20 w21 w22 w23 w24 w25 w26 w27 w28 w29
                       w30 w31 w32 w33 w34 w35 w36 w37 w38 w39
                       w40 w41 w42 w43 w44 w45 w46 w47 w48 w49
                       w50 w51 w52 w53 w54 w55 w56 w57 w58 w59
                       w60 w61 w62 w63

data SHA512Sched = SHA512Sched !Word64 !Word64 !Word64 !Word64 !Word64 --  0- 4
                               !Word64 !Word64 !Word64 !Word64 !Word64 --  5- 9
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 10-14
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 15-19
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 20-24
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 25-29
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 30-34
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 35-39
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 40-44
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 45-49
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 50-54
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 55-59
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 60-64
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 65-69
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 70-74
                               !Word64 !Word64 !Word64 !Word64 !Word64 -- 75-79

getSHA512Sched :: Get SHA512Sched
getSHA512Sched = do
  w00 <- getWord64be
  w01 <- getWord64be
  w02 <- getWord64be
  w03 <- getWord64be
  w04 <- getWord64be
  w05 <- getWord64be
  w06 <- getWord64be
  w07 <- getWord64be
  w08 <- getWord64be
  w09 <- getWord64be
  w10 <- getWord64be
  w11 <- getWord64be
  w12 <- getWord64be
  w13 <- getWord64be
  w14 <- getWord64be
  w15 <- getWord64be
  let w16 = (lsig512_1 w14) + w09 + (lsig512_0 w01) + w00
      w17 = (lsig512_1 w15) + w10 + (lsig512_0 w02) + w01
      w18 = (lsig512_1 w16) + w11 + (lsig512_0 w03) + w02
      w19 = (lsig512_1 w17) + w12 + (lsig512_0 w04) + w03
      w20 = (lsig512_1 w18) + w13 + (lsig512_0 w05) + w04
      w21 = (lsig512_1 w19) + w14 + (lsig512_0 w06) + w05
      w22 = (lsig512_1 w20) + w15 + (lsig512_0 w07) + w06
      w23 = (lsig512_1 w21) + w16 + (lsig512_0 w08) + w07
      w24 = (lsig512_1 w22) + w17 + (lsig512_0 w09) + w08
      w25 = (lsig512_1 w23) + w18 + (lsig512_0 w10) + w09
      w26 = (lsig512_1 w24) + w19 + (lsig512_0 w11) + w10
      w27 = (lsig512_1 w25) + w20 + (lsig512_0 w12) + w11
      w28 = (lsig512_1 w26) + w21 + (lsig512_0 w13) + w12
      w29 = (lsig512_1 w27) + w22 + (lsig512_0 w14) + w13
      w30 = (lsig512_1 w28) + w23 + (lsig512_0 w15) + w14
      w31 = (lsig512_1 w29) + w24 + (lsig512_0 w16) + w15
      w32 = (lsig512_1 w30) + w25 + (lsig512_0 w17) + w16
      w33 = (lsig512_1 w31) + w26 + (lsig512_0 w18) + w17
      w34 = (lsig512_1 w32) + w27 + (lsig512_0 w19) + w18
      w35 = (lsig512_1 w33) + w28 + (lsig512_0 w20) + w19
      w36 = (lsig512_1 w34) + w29 + (lsig512_0 w21) + w20
      w37 = (lsig512_1 w35) + w30 + (lsig512_0 w22) + w21
      w38 = (lsig512_1 w36) + w31 + (lsig512_0 w23) + w22
      w39 = (lsig512_1 w37) + w32 + (lsig512_0 w24) + w23
      w40 = (lsig512_1 w38) + w33 + (lsig512_0 w25) + w24
      w41 = (lsig512_1 w39) + w34 + (lsig512_0 w26) + w25
      w42 = (lsig512_1 w40) + w35 + (lsig512_0 w27) + w26
      w43 = (lsig512_1 w41) + w36 + (lsig512_0 w28) + w27
      w44 = (lsig512_1 w42) + w37 + (lsig512_0 w29) + w28
      w45 = (lsig512_1 w43) + w38 + (lsig512_0 w30) + w29
      w46 = (lsig512_1 w44) + w39 + (lsig512_0 w31) + w30
      w47 = (lsig512_1 w45) + w40 + (lsig512_0 w32) + w31
      w48 = (lsig512_1 w46) + w41 + (lsig512_0 w33) + w32
      w49 = (lsig512_1 w47) + w42 + (lsig512_0 w34) + w33
      w50 = (lsig512_1 w48) + w43 + (lsig512_0 w35) + w34
      w51 = (lsig512_1 w49) + w44 + (lsig512_0 w36) + w35
      w52 = (lsig512_1 w50) + w45 + (lsig512_0 w37) + w36
      w53 = (lsig512_1 w51) + w46 + (lsig512_0 w38) + w37
      w54 = (lsig512_1 w52) + w47 + (lsig512_0 w39) + w38
      w55 = (lsig512_1 w53) + w48 + (lsig512_0 w40) + w39
      w56 = (lsig512_1 w54) + w49 + (lsig512_0 w41) + w40
      w57 = (lsig512_1 w55) + w50 + (lsig512_0 w42) + w41
      w58 = (lsig512_1 w56) + w51 + (lsig512_0 w43) + w42
      w59 = (lsig512_1 w57) + w52 + (lsig512_0 w44) + w43
      w60 = (lsig512_1 w58) + w53 + (lsig512_0 w45) + w44
      w61 = (lsig512_1 w59) + w54 + (lsig512_0 w46) + w45
      w62 = (lsig512_1 w60) + w55 + (lsig512_0 w47) + w46
      w63 = (lsig512_1 w61) + w56 + (lsig512_0 w48) + w47
      w64 = (lsig512_1 w62) + w57 + (lsig512_0 w49) + w48
      w65 = (lsig512_1 w63) + w58 + (lsig512_0 w50) + w49
      w66 = (lsig512_1 w64) + w59 + (lsig512_0 w51) + w50
      w67 = (lsig512_1 w65) + w60 + (lsig512_0 w52) + w51
      w68 = (lsig512_1 w66) + w61 + (lsig512_0 w53) + w52
      w69 = (lsig512_1 w67) + w62 + (lsig512_0 w54) + w53
      w70 = (lsig512_1 w68) + w63 + (lsig512_0 w55) + w54
      w71 = (lsig512_1 w69) + w64 + (lsig512_0 w56) + w55
      w72 = (lsig512_1 w70) + w65 + (lsig512_0 w57) + w56
      w73 = (lsig512_1 w71) + w66 + (lsig512_0 w58) + w57
      w74 = (lsig512_1 w72) + w67 + (lsig512_0 w59) + w58
      w75 = (lsig512_1 w73) + w68 + (lsig512_0 w60) + w59
      w76 = (lsig512_1 w74) + w69 + (lsig512_0 w61) + w60
      w77 = (lsig512_1 w75) + w70 + (lsig512_0 w62) + w61
      w78 = (lsig512_1 w76) + w71 + (lsig512_0 w63) + w62
      w79 = (lsig512_1 w77) + w72 + (lsig512_0 w64) + w63
  return $ SHA512Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09 
                       w10 w11 w12 w13 w14 w15 w16 w17 w18 w19 
                       w20 w21 w22 w23 w24 w25 w26 w27 w28 w29 
                       w30 w31 w32 w33 w34 w35 w36 w37 w38 w39 
                       w40 w41 w42 w43 w44 w45 w46 w47 w48 w49 
                       w50 w51 w52 w53 w54 w55 w56 w57 w58 w59 
                       w60 w61 w62 w63 w64 w65 w66 w67 w68 w69 
                       w70 w71 w72 w73 w74 w75 w76 w77 w78 w79 

-- --------------------------------------------------------------------------
--
-- SHA Block Processors
--
-- --------------------------------------------------------------------------

processSHA1Block :: SHA1State -> Get SHA1State
processSHA1Block !s00@(SHA1S a00 b00 c00 d00 e00) = do
  (SHA1Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09
             w10 w11 w12 w13 w14 w15 w16 w17 w18 w19
             w20 w21 w22 w23 w24 w25 w26 w27 w28 w29
             w30 w31 w32 w33 w34 w35 w36 w37 w38 w39
             w40 w41 w42 w43 w44 w45 w46 w47 w48 w49
             w50 w51 w52 w53 w54 w55 w56 w57 w58 w59
             w60 w61 w62 w63 w64 w65 w66 w67 w68 w69
             w70 w71 w72 w73 w74 w75 w76 w77 w78 w79) <- getSHA1Sched
  let !s01 = step s00 (sha1_k ! 00) (sha1_f Arr.! 00) w00
      !s02 = step s01 (sha1_k ! 01) (sha1_f Arr.! 01) w01
      !s03 = step s02 (sha1_k ! 02) (sha1_f Arr.! 02) w02
      !s04 = step s03 (sha1_k ! 03) (sha1_f Arr.! 03) w03
      !s05 = step s04 (sha1_k ! 04) (sha1_f Arr.! 04) w04
      !s06 = step s05 (sha1_k ! 05) (sha1_f Arr.! 05) w05
      !s07 = step s06 (sha1_k ! 06) (sha1_f Arr.! 06) w06
      !s08 = step s07 (sha1_k ! 07) (sha1_f Arr.! 07) w07
      !s09 = step s08 (sha1_k ! 08) (sha1_f Arr.! 08) w08
      !s10 = step s09 (sha1_k ! 09) (sha1_f Arr.! 09) w09
      !s11 = step s10 (sha1_k ! 10) (sha1_f Arr.! 10) w10
      !s12 = step s11 (sha1_k ! 11) (sha1_f Arr.! 11) w11
      !s13 = step s12 (sha1_k ! 12) (sha1_f Arr.! 12) w12
      !s14 = step s13 (sha1_k ! 13) (sha1_f Arr.! 13) w13
      !s15 = step s14 (sha1_k ! 14) (sha1_f Arr.! 14) w14
      !s16 = step s15 (sha1_k ! 15) (sha1_f Arr.! 15) w15
      !s17 = step s16 (sha1_k ! 16) (sha1_f Arr.! 16) w16
      !s18 = step s17 (sha1_k ! 17) (sha1_f Arr.! 17) w17
      !s19 = step s18 (sha1_k ! 18) (sha1_f Arr.! 18) w18
      !s20 = step s19 (sha1_k ! 19) (sha1_f Arr.! 19) w19
      !s21 = step s20 (sha1_k ! 20) (sha1_f Arr.! 20) w20
      !s22 = step s21 (sha1_k ! 21) (sha1_f Arr.! 21) w21
      !s23 = step s22 (sha1_k ! 22) (sha1_f Arr.! 22) w22
      !s24 = step s23 (sha1_k ! 23) (sha1_f Arr.! 23) w23
      !s25 = step s24 (sha1_k ! 24) (sha1_f Arr.! 24) w24
      !s26 = step s25 (sha1_k ! 25) (sha1_f Arr.! 25) w25
      !s27 = step s26 (sha1_k ! 26) (sha1_f Arr.! 26) w26
      !s28 = step s27 (sha1_k ! 27) (sha1_f Arr.! 27) w27
      !s29 = step s28 (sha1_k ! 28) (sha1_f Arr.! 28) w28
      !s30 = step s29 (sha1_k ! 29) (sha1_f Arr.! 29) w29
      !s31 = step s30 (sha1_k ! 30) (sha1_f Arr.! 30) w30
      !s32 = step s31 (sha1_k ! 31) (sha1_f Arr.! 31) w31
      !s33 = step s32 (sha1_k ! 32) (sha1_f Arr.! 32) w32
      !s34 = step s33 (sha1_k ! 33) (sha1_f Arr.! 33) w33
      !s35 = step s34 (sha1_k ! 34) (sha1_f Arr.! 34) w34
      !s36 = step s35 (sha1_k ! 35) (sha1_f Arr.! 35) w35
      !s37 = step s36 (sha1_k ! 36) (sha1_f Arr.! 36) w36
      !s38 = step s37 (sha1_k ! 37) (sha1_f Arr.! 37) w37
      !s39 = step s38 (sha1_k ! 38) (sha1_f Arr.! 38) w38
      !s40 = step s39 (sha1_k ! 39) (sha1_f Arr.! 39) w39
      !s41 = step s40 (sha1_k ! 40) (sha1_f Arr.! 40) w40
      !s42 = step s41 (sha1_k ! 41) (sha1_f Arr.! 41) w41
      !s43 = step s42 (sha1_k ! 42) (sha1_f Arr.! 42) w42
      !s44 = step s43 (sha1_k ! 43) (sha1_f Arr.! 43) w43
      !s45 = step s44 (sha1_k ! 44) (sha1_f Arr.! 44) w44
      !s46 = step s45 (sha1_k ! 45) (sha1_f Arr.! 45) w45
      !s47 = step s46 (sha1_k ! 46) (sha1_f Arr.! 46) w46
      !s48 = step s47 (sha1_k ! 47) (sha1_f Arr.! 47) w47
      !s49 = step s48 (sha1_k ! 48) (sha1_f Arr.! 48) w48
      !s50 = step s49 (sha1_k ! 49) (sha1_f Arr.! 49) w49
      !s51 = step s50 (sha1_k ! 50) (sha1_f Arr.! 50) w50
      !s52 = step s51 (sha1_k ! 51) (sha1_f Arr.! 51) w51
      !s53 = step s52 (sha1_k ! 52) (sha1_f Arr.! 52) w52
      !s54 = step s53 (sha1_k ! 53) (sha1_f Arr.! 53) w53
      !s55 = step s54 (sha1_k ! 54) (sha1_f Arr.! 54) w54
      !s56 = step s55 (sha1_k ! 55) (sha1_f Arr.! 55) w55
      !s57 = step s56 (sha1_k ! 56) (sha1_f Arr.! 56) w56
      !s58 = step s57 (sha1_k ! 57) (sha1_f Arr.! 57) w57
      !s59 = step s58 (sha1_k ! 58) (sha1_f Arr.! 58) w58
      !s60 = step s59 (sha1_k ! 59) (sha1_f Arr.! 59) w59
      !s61 = step s60 (sha1_k ! 60) (sha1_f Arr.! 60) w60
      !s62 = step s61 (sha1_k ! 61) (sha1_f Arr.! 61) w61
      !s63 = step s62 (sha1_k ! 62) (sha1_f Arr.! 62) w62
      !s64 = step s63 (sha1_k ! 63) (sha1_f Arr.! 63) w63
      !s65 = step s64 (sha1_k ! 64) (sha1_f Arr.! 64) w64
      !s66 = step s65 (sha1_k ! 65) (sha1_f Arr.! 65) w65
      !s67 = step s66 (sha1_k ! 66) (sha1_f Arr.! 66) w66
      !s68 = step s67 (sha1_k ! 67) (sha1_f Arr.! 67) w67
      !s69 = step s68 (sha1_k ! 68) (sha1_f Arr.! 68) w68
      !s70 = step s69 (sha1_k ! 69) (sha1_f Arr.! 69) w69
      !s71 = step s70 (sha1_k ! 70) (sha1_f Arr.! 70) w70
      !s72 = step s71 (sha1_k ! 71) (sha1_f Arr.! 71) w71
      !s73 = step s72 (sha1_k ! 72) (sha1_f Arr.! 72) w72
      !s74 = step s73 (sha1_k ! 73) (sha1_f Arr.! 73) w73
      !s75 = step s74 (sha1_k ! 74) (sha1_f Arr.! 74) w74
      !s76 = step s75 (sha1_k ! 75) (sha1_f Arr.! 75) w75
      !s77 = step s76 (sha1_k ! 76) (sha1_f Arr.! 76) w76
      !s78 = step s77 (sha1_k ! 77) (sha1_f Arr.! 77) w77
      !s79 = step s78 (sha1_k ! 78) (sha1_f Arr.! 78) w78
      !s80 = step s79 (sha1_k ! 79) (sha1_f Arr.! 79) w79
      SHA1S a80 b80 c80 d80 e80 = s80
  return $ SHA1S (a00 + a80) (b00 + b80) (c00 + c80) (d00 + d80) (e00 + e80)
 where
  step (SHA1S a b c d e) k f w = SHA1S a' b' c' d' e'
   where a' = (rotate a 5) + (f b c d) + e + k + w
         b' = a
         c' = rotate b 30
         d' = c
         e' = d
   
processSHA256Block :: SHA256State -> Get SHA256State
processSHA256Block !s00@(SHA256S a00 b00 c00 d00 e00 f00 g00 h00) = do
  (SHA256Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09
               w10 w11 w12 w13 w14 w15 w16 w17 w18 w19
               w20 w21 w22 w23 w24 w25 w26 w27 w28 w29
               w30 w31 w32 w33 w34 w35 w36 w37 w38 w39
               w40 w41 w42 w43 w44 w45 w46 w47 w48 w49
               w50 w51 w52 w53 w54 w55 w56 w57 w58 w59
               w60 w61 w62 w63) <- getSHA256Sched
  let !s01 = step s00 (sha256_k ! 00) w00
      !s02 = step s01 (sha256_k ! 01) w01
      !s03 = step s02 (sha256_k ! 02) w02
      !s04 = step s03 (sha256_k ! 03) w03
      !s05 = step s04 (sha256_k ! 04) w04
      !s06 = step s05 (sha256_k ! 05) w05
      !s07 = step s06 (sha256_k ! 06) w06
      !s08 = step s07 (sha256_k ! 07) w07
      !s09 = step s08 (sha256_k ! 08) w08
      !s10 = step s09 (sha256_k ! 09) w09
      !s11 = step s10 (sha256_k ! 10) w10
      !s12 = step s11 (sha256_k ! 11) w11
      !s13 = step s12 (sha256_k ! 12) w12
      !s14 = step s13 (sha256_k ! 13) w13
      !s15 = step s14 (sha256_k ! 14) w14
      !s16 = step s15 (sha256_k ! 15) w15
      !s17 = step s16 (sha256_k ! 16) w16
      !s18 = step s17 (sha256_k ! 17) w17
      !s19 = step s18 (sha256_k ! 18) w18
      !s20 = step s19 (sha256_k ! 19) w19
      !s21 = step s20 (sha256_k ! 20) w20
      !s22 = step s21 (sha256_k ! 21) w21
      !s23 = step s22 (sha256_k ! 22) w22
      !s24 = step s23 (sha256_k ! 23) w23
      !s25 = step s24 (sha256_k ! 24) w24
      !s26 = step s25 (sha256_k ! 25) w25
      !s27 = step s26 (sha256_k ! 26) w26
      !s28 = step s27 (sha256_k ! 27) w27
      !s29 = step s28 (sha256_k ! 28) w28
      !s30 = step s29 (sha256_k ! 29) w29
      !s31 = step s30 (sha256_k ! 30) w30
      !s32 = step s31 (sha256_k ! 31) w31
      !s33 = step s32 (sha256_k ! 32) w32
      !s34 = step s33 (sha256_k ! 33) w33
      !s35 = step s34 (sha256_k ! 34) w34
      !s36 = step s35 (sha256_k ! 35) w35
      !s37 = step s36 (sha256_k ! 36) w36
      !s38 = step s37 (sha256_k ! 37) w37
      !s39 = step s38 (sha256_k ! 38) w38
      !s40 = step s39 (sha256_k ! 39) w39
      !s41 = step s40 (sha256_k ! 40) w40
      !s42 = step s41 (sha256_k ! 41) w41
      !s43 = step s42 (sha256_k ! 42) w42
      !s44 = step s43 (sha256_k ! 43) w43
      !s45 = step s44 (sha256_k ! 44) w44
      !s46 = step s45 (sha256_k ! 45) w45
      !s47 = step s46 (sha256_k ! 46) w46
      !s48 = step s47 (sha256_k ! 47) w47
      !s49 = step s48 (sha256_k ! 48) w48
      !s50 = step s49 (sha256_k ! 49) w49
      !s51 = step s50 (sha256_k ! 50) w50
      !s52 = step s51 (sha256_k ! 51) w51
      !s53 = step s52 (sha256_k ! 52) w52
      !s54 = step s53 (sha256_k ! 53) w53
      !s55 = step s54 (sha256_k ! 54) w54
      !s56 = step s55 (sha256_k ! 55) w55
      !s57 = step s56 (sha256_k ! 56) w56
      !s58 = step s57 (sha256_k ! 57) w57
      !s59 = step s58 (sha256_k ! 58) w58
      !s60 = step s59 (sha256_k ! 59) w59
      !s61 = step s60 (sha256_k ! 60) w60
      !s62 = step s61 (sha256_k ! 61) w61
      !s63 = step s62 (sha256_k ! 62) w62
      !s64 = step s63 (sha256_k ! 63) w63
      SHA256S a64 b64 c64 d64 e64 f64 g64 h64 = s64
  return $ SHA256S (a00 + a64) (b00 + b64) (c00 + c64) (d00 + d64)
                   (e00 + e64) (f00 + f64) (g00 + g64) (h00 + h64)
 where
  step (SHA256S a b c d e f g h) k w = SHA256S a' b' c' d' e' f' g' h' 
   where
    t1 = h + bsig256_1 e + ch e f g + k + w
    t2 = bsig256_0 a + maj a b c
    h' = g
    g' = f
    f' = e
    e' = d + t1
    d' = c
    c' = b
    b' = a
    a' = t1 + t2

processSHA512Block :: SHA512State -> Get SHA512State
processSHA512Block !s00@(SHA512S a00 b00 c00 d00 e00 f00 g00 h00) = do
  (SHA512Sched w00 w01 w02 w03 w04 w05 w06 w07 w08 w09
               w10 w11 w12 w13 w14 w15 w16 w17 w18 w19
               w20 w21 w22 w23 w24 w25 w26 w27 w28 w29
               w30 w31 w32 w33 w34 w35 w36 w37 w38 w39
               w40 w41 w42 w43 w44 w45 w46 w47 w48 w49
               w50 w51 w52 w53 w54 w55 w56 w57 w58 w59
               w60 w61 w62 w63 w64 w65 w66 w67 w68 w69
               w70 w71 w72 w73 w74 w75 w76 w77 w78 w79) <- getSHA512Sched
  let !s01 = step s00 (sha512_k ! 00) w00
      !s02 = step s01 (sha512_k ! 01) w01
      !s03 = step s02 (sha512_k ! 02) w02
      !s04 = step s03 (sha512_k ! 03) w03
      !s05 = step s04 (sha512_k ! 04) w04
      !s06 = step s05 (sha512_k ! 05) w05
      !s07 = step s06 (sha512_k ! 06) w06
      !s08 = step s07 (sha512_k ! 07) w07
      !s09 = step s08 (sha512_k ! 08) w08
      !s10 = step s09 (sha512_k ! 09) w09
      !s11 = step s10 (sha512_k ! 10) w10
      !s12 = step s11 (sha512_k ! 11) w11
      !s13 = step s12 (sha512_k ! 12) w12
      !s14 = step s13 (sha512_k ! 13) w13
      !s15 = step s14 (sha512_k ! 14) w14
      !s16 = step s15 (sha512_k ! 15) w15
      !s17 = step s16 (sha512_k ! 16) w16
      !s18 = step s17 (sha512_k ! 17) w17
      !s19 = step s18 (sha512_k ! 18) w18
      !s20 = step s19 (sha512_k ! 19) w19
      !s21 = step s20 (sha512_k ! 20) w20
      !s22 = step s21 (sha512_k ! 21) w21
      !s23 = step s22 (sha512_k ! 22) w22
      !s24 = step s23 (sha512_k ! 23) w23
      !s25 = step s24 (sha512_k ! 24) w24
      !s26 = step s25 (sha512_k ! 25) w25
      !s27 = step s26 (sha512_k ! 26) w26
      !s28 = step s27 (sha512_k ! 27) w27
      !s29 = step s28 (sha512_k ! 28) w28
      !s30 = step s29 (sha512_k ! 29) w29
      !s31 = step s30 (sha512_k ! 30) w30
      !s32 = step s31 (sha512_k ! 31) w31
      !s33 = step s32 (sha512_k ! 32) w32
      !s34 = step s33 (sha512_k ! 33) w33
      !s35 = step s34 (sha512_k ! 34) w34
      !s36 = step s35 (sha512_k ! 35) w35
      !s37 = step s36 (sha512_k ! 36) w36
      !s38 = step s37 (sha512_k ! 37) w37
      !s39 = step s38 (sha512_k ! 38) w38
      !s40 = step s39 (sha512_k ! 39) w39
      !s41 = step s40 (sha512_k ! 40) w40
      !s42 = step s41 (sha512_k ! 41) w41
      !s43 = step s42 (sha512_k ! 42) w42
      !s44 = step s43 (sha512_k ! 43) w43
      !s45 = step s44 (sha512_k ! 44) w44
      !s46 = step s45 (sha512_k ! 45) w45
      !s47 = step s46 (sha512_k ! 46) w46
      !s48 = step s47 (sha512_k ! 47) w47
      !s49 = step s48 (sha512_k ! 48) w48
      !s50 = step s49 (sha512_k ! 49) w49
      !s51 = step s50 (sha512_k ! 50) w50
      !s52 = step s51 (sha512_k ! 51) w51
      !s53 = step s52 (sha512_k ! 52) w52
      !s54 = step s53 (sha512_k ! 53) w53
      !s55 = step s54 (sha512_k ! 54) w54
      !s56 = step s55 (sha512_k ! 55) w55
      !s57 = step s56 (sha512_k ! 56) w56
      !s58 = step s57 (sha512_k ! 57) w57
      !s59 = step s58 (sha512_k ! 58) w58
      !s60 = step s59 (sha512_k ! 59) w59
      !s61 = step s60 (sha512_k ! 60) w60
      !s62 = step s61 (sha512_k ! 61) w61
      !s63 = step s62 (sha512_k ! 62) w62
      !s64 = step s63 (sha512_k ! 63) w63
      !s65 = step s64 (sha512_k ! 64) w64
      !s66 = step s65 (sha512_k ! 65) w65
      !s67 = step s66 (sha512_k ! 66) w66
      !s68 = step s67 (sha512_k ! 67) w67
      !s69 = step s68 (sha512_k ! 68) w68
      !s70 = step s69 (sha512_k ! 69) w69
      !s71 = step s70 (sha512_k ! 70) w70
      !s72 = step s71 (sha512_k ! 71) w71
      !s73 = step s72 (sha512_k ! 72) w72
      !s74 = step s73 (sha512_k ! 73) w73
      !s75 = step s74 (sha512_k ! 74) w74
      !s76 = step s75 (sha512_k ! 75) w75
      !s77 = step s76 (sha512_k ! 76) w76
      !s78 = step s77 (sha512_k ! 77) w77
      !s79 = step s78 (sha512_k ! 78) w78
      !s80 = step s79 (sha512_k ! 79) w79
      SHA512S a80 b80 c80 d80 e80 f80 g80 h80 = s80
  return $ SHA512S (a00 + a80) (b00 + b80) (c00 + c80) (d00 + d80)
                   (e00 + e80) (f00 + f80) (g00 + g80) (h00 + h80)
 where
  step (SHA512S a b c d e f g h) k w = SHA512S a' b' c' d' e' f' g' h'
   where
    t1 = h + bsig512_1 e + ch e f g + k + w
    t2 = bsig512_0 a + maj a b c
    h' = g
    g' = f
    f' = e
    e' = d + t1
    d' = c
    c' = b
    b' = a
    a' = t1 + t2

-- --------------------------------------------------------------------------
--
-- Run the routines
--
-- --------------------------------------------------------------------------

runSHA :: a -> (a -> Get a) -> ByteString -> a
runSHA s nextChunk input = runGet (getAll s) input
 where 
  getAll s_in = do
    done <- isEmpty
    if done
      then return s_in
      else do s_out <- nextChunk s_in
              getAll s_out

sha1 :: ByteString -> Digest
sha1 bs_in = Digest bs_out
 where
  bs_pad = padSHA1 bs_in
  fstate = runSHA initialSHA1State processSHA1Block bs_pad
  bs_out = runPut $ synthesizeSHA1 fstate

-- |Compute the SHA-224 hash of the given ByteString. Note that SHA-224 and
-- SHA-384 differ only slightly from SHA-256 and SHA-512, and use truncated
-- versions of the resulting hashes. So using 224/384 may not, in fact, save
-- you very much ...
sha224 :: ByteString -> Digest
sha224 bs_in = Digest bs_out
 where
  bs_pad = padSHA1 bs_in
  fstate = runSHA initialSHA224State processSHA256Block bs_pad
  bs_out = runPut $ synthesizeSHA224 fstate

-- |Compute the SHA-256 hash of the given ByteString. The output is guaranteed
-- to be exactly 256 bits, or 32 bytes, long. If your security requirements 
-- are pretty serious, this is a good choice. For truly significant security
-- concerns, however, you might try one of the bigger options.
sha256 :: ByteString -> Digest
sha256 bs_in = Digest bs_out
 where
  bs_pad = padSHA1 bs_in
  fstate = runSHA initialSHA256State processSHA256Block bs_pad
  bs_out = runPut $ synthesizeSHA256 fstate

-- |Compute the SHA-384 hash of the given ByteString. Yup, you guessed it, 
-- the output will be exactly 384 bits, or 48 bytes, long.
sha384 :: ByteString -> Digest
sha384 bs_in = Digest bs_out
 where
  bs_pad = padSHA512 bs_in
  fstate = runSHA initialSHA384State processSHA512Block bs_pad
  bs_out = runPut $ synthesizeSHA384 fstate

-- |For those for whom only the biggest hashes will do, this computes the
-- SHA-512 hash of the given ByteString. The output will be 64 bytes, or
-- 512 bits, long.
sha512 :: ByteString -> Digest
sha512 bs_in = Digest bs_out
 where
  bs_pad = padSHA512 bs_in
  fstate = runSHA initialSHA512State processSHA512Block bs_pad
  bs_out = runPut $ synthesizeSHA512 fstate

-- --------------------------------------------------------------------------
--
--                                OTHER
--
-- --------------------------------------------------------------------------


-- | Convert a digest to a string.
-- The digest is rendered as fixed with hexadecimal number.
showDigest :: Digest -> String
showDigest (Digest bs) = showDigestBS bs

-- |Prints out a bytestring in hexadecimal. Just for convenience.
showDigestBS :: ByteString -> String
showDigestBS bs = concatMap paddedShowHex $ BS.unpack bs
 where
   paddedShowHex x = toHex (x `shiftR` 4) ++ toHex (x .&. 0xf)
   toHex x = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
             !! (fromIntegral x)

-- | Convert a digest to an Integer.
integerDigest :: Digest -> Integer
integerDigest (Digest bs) = BS.foldl' addShift 0 bs
 where addShift n y = (n `shiftL` 8) .|. fromIntegral y

-- | Convert a digest to a ByteString.
bytestringDigest :: Digest -> ByteString
bytestringDigest (Digest bs) = bs
