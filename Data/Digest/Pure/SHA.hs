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
       , sha_1_256_pad, sha_384_512_pad
#endif
       )
 where

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
--                              SHA-1
--
-- --------------------------------------------------------------------------

data State32 = S32 !Word32 !Word32 !Word32 !Word32 
                   !Word32 !Word32 !Word32 !Word32

-- |Compute the SHA-1 hash of the given ByteString. The output is guaranteed
-- to be exactly 160 bits, or 20 bytes, long. This is a good default for
-- programs that need a good, but not necessarily hyper-secure, hash function.
sha1 :: ByteString -> Digest
sha1 bs = Digest $ compute_sha1_hash sha1_initial_state chunked_bs
 where
  padded_bs  = sha_1_256_pad bs
  chunked_bs = chunk 512 padded_bs

compute_sha1_hash :: State32 -> [ByteString] -> ByteString
compute_sha1_hash (S32 a b c d e _ _ _) [] = 
  BS.concat $ map (toBigEndianBS 32) [a,b,c,d,e]
compute_sha1_hash ins@(S32 a b c d e _ _ _) (first:rest) =
  compute_sha1_hash next rest
 where
  x = foldl tiny_step1 ins (zip3 (message_schedule_1 first) sha1_ks [0..79])
  S32 a' b' c' d' e' _ _ _ = x
  next = S32 (a+a') (b+b') (c+c') (d+d') (e+e') 0 0 0

message_schedule_1 :: ByteString -> [Word32]
message_schedule_1 bs = genSched (reverse $ map fromBigEndianBS $ chunk 32 bs)
 where
  genSched curs | length curs == 80 = reverse curs
                | otherwise =
   -- note that we keep curs in reversed order to make the indexing work out
   let w_3 = curs !! 2
       w_8 = curs !! 7
       w_14 = curs !! 13
       w_16 = curs !! 15
       base = w_3 `xor` w_8 `xor` w_14 `xor` w_16
   in genSched (rotate base 1 : curs) 
             
tiny_step1 :: State32 -> (Word32, Word32, Word32) -> State32
tiny_step1 (S32 a b c d e _ _ _) (w, k, t) = S32 a' b' c' d' e' 0 0 0
 where
  a' = (rotate a 5) + (sha1_f t b c d) + e + k + w
  e' = d
  d' = c
  c' = rotate b 30
  b' = a

sha1_f :: Word32 -> Word32 -> Word32 -> Word32 -> Word32
sha1_f t x y z 
  | t <= 19                = (x .&. y) `xor` ((complement x) .&. z)
  | (t >= 20) && (t <= 39) = x `xor` y `xor` z
  | (t >= 40) && (t <= 59) = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)
  | (t >= 60) && (t <= 79) = x `xor` y `xor` z
  | otherwise              = error $ "Illegal SHA-1 f function number "++show t

sha1_initial_state :: State32
sha1_initial_state = 
  S32 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0 0 0 0

sha1_ks :: [Word32]
sha1_ks = map gen_k [0 .. 79]
 where
  gen_k :: Int -> Word32 
  gen_k x | x <= 19                = 0x5a827999
          | (x >= 20) && (x <= 39) = 0x6ed9eba1
          | (x >= 40) && (x <= 59) = 0x8f1bbcdc
          | otherwise              = 0xca62c1d6

-- --------------------------------------------------------------------------
--
--                              SHA-224
--
-- --------------------------------------------------------------------------

-- |Compute the SHA-224 hash of the given ByteString. Note that SHA-224 and
-- SHA-384 differ only slightly from SHA-256 and SHA-512, and use truncated
-- versions of the resulting hashes. So using 224/384 may not, in fact, save
-- you very much ...
sha224 ::  ByteString -> Digest
sha224 bs = Digest $ BS.take 28
                   $ compute_sha256_hash sha224_initial_state chunked_bs
 where
  padded_bs  = sha_1_256_pad bs
  chunked_bs = chunk 512 padded_bs

sha224_initial_state :: State32
sha224_initial_state = S32 0xc1059ed8 0x367cd507 0x3070dd17 0xf70e5939
                           0xffc00b31 0x68581511 0x64f98fa7 0xbefa4fa4
 
-- --------------------------------------------------------------------------
--
--                              SHA-256
--
-- --------------------------------------------------------------------------

-- |Compute the SHA-256 hash of the given ByteString. The output is guaranteed
-- to be exactly 256 bits, or 32 bytes, long. If your security requirements 
-- are pretty serious, this is a good choice. For truly significant security
-- concerns, however, you might try one of the bigger options.
sha256 :: ByteString -> Digest
sha256 bs = Digest $ compute_sha256_hash sha256_initial_state chunked_bs
 where
  padded_bs  = sha_1_256_pad bs
  chunked_bs = chunk 512 padded_bs

compute_sha256_hash :: State32 -> [ByteString] -> ByteString
compute_sha256_hash (S32 a b c d e f g h) [] =
  BS.concat $ map (toBigEndianBS 32) [a,b,c,d,e,f,g,h]
compute_sha256_hash ins@(S32 a b c d e f g h) (first:rest) =
  compute_sha256_hash next rest
 where
  x = foldl tiny_step256 ins (zip (message_schedule_256 first) sha256_ks)
  S32 a' b' c' d' e' f' g' h' = x
  next = S32 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')

message_schedule_256 :: ByteString -> [Word32]
message_schedule_256 bs = genSched (reverse $ map fromBigEndianBS $ chunk 32 bs)
 where
  genSched curs | length curs == 64 = reverse curs
                | otherwise =
   let sw2 = small_sigma_256_1 $ curs !! 1
       w7 = curs !! 6
       sw15 = small_sigma_256_0 $ curs !! 14
       w16 = curs !! 15
       new_guy = sw2 + w7 + sw15 + w16 
   in genSched (new_guy : curs)

tiny_step256 :: State32 -> (Word32, Word32) -> State32
tiny_step256 (S32 a b c d e f g h) (w, k) = S32 a' b' c' d' e' f' g' h'
 where
  a' = t1 + t2
  b' = a
  c' = b
  d' = c
  e' = d + t1
  f' = e
  g' = f
  h' = g
  t1 = h + (big_sigma_256_1 e) + (ch256 e f g) + k + w
  t2 = big_sigma_256_0 a + maj256 a b c

ch256 :: Word32 -> Word32 -> Word32 -> Word32
ch256 x y z = (x .&. y) `xor` ((complement x) .&. z)

maj256 :: Word32 -> Word32 -> Word32 -> Word32
maj256 x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)

big_sigma_256_0 :: Word32 -> Word32
big_sigma_256_0 x = 
  (x `rotate` (-2)) `xor` (x `rotate` (-13)) `xor` (x `rotate` (-22))

big_sigma_256_1 :: Word32 -> Word32
big_sigma_256_1 x = 
  (x `rotate` (-6)) `xor` (x `rotate` (-11)) `xor` (x `rotate` (-25))

small_sigma_256_0 :: Word32 -> Word32
small_sigma_256_0 x =
  (x `rotate` (-7)) `xor` (x `rotate` (-18)) `xor` (x `shiftR` 3)

small_sigma_256_1 :: Word32 -> Word32
small_sigma_256_1 x =
  (x `rotate` (-17)) `xor` (x `rotate` (-19)) `xor` (x `shiftR` 10)

sha256_initial_state :: State32
sha256_initial_state = 
  S32 0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
      0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19

sha256_ks :: [Word32]
sha256_ks = 
  [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
   0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
   0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
   0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
   0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
   0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

-- --------------------------------------------------------------------------
--
--                              SHA-384
--
-- --------------------------------------------------------------------------

data State64 = S64 Word64 Word64 Word64 Word64 Word64 Word64 Word64 Word64

instance Show State64 where
  show (S64 a b c d e f g h) =
    "S64 " ++ concatMap ((++ " ") .  showDigestBS . toBigEndianBS 64) [a,b,c,d,e,f,g,h]

-- |Compute the SHA-384 hash of the given ByteString. Yup, you guessed it, 
-- the output will be exactly 384 bits, or 48 bytes, long.
sha384 :: ByteString -> Digest
sha384 bs = Digest $ BS.take 48
                   $ compute_sha512_hash sha384_initial_state chunked_bs
 where
  padded_bs  = sha_384_512_pad bs
  chunked_bs = chunk 1024 padded_bs

sha384_initial_state :: State64
sha384_initial_state =
 S64 0xcbbb9d5dc1059ed8 0x629a292a367cd507 0x9159015a3070dd17 
     0x152fecd8f70e5939 0x67332667ffc00b31 0x8eb44a8768581511 
     0xdb0c2e0d64f98fa7 0x47b5481dbefa4fa4

-- --------------------------------------------------------------------------
--
--                              SHA-512
--
-- --------------------------------------------------------------------------

-- |For those for whom only the biggest hashes will do, this computes the
-- SHA-512 hash of the given ByteString. The output will be 64 bytes, or
-- 512 bits, long.
sha512 :: ByteString -> Digest
sha512 bs = Digest $ compute_sha512_hash sha512_initial_state chunked_bs
 where
  padded_bs  = sha_384_512_pad bs
  chunked_bs = chunk 1024 padded_bs

compute_sha512_hash :: State64 -> [ByteString] -> ByteString
compute_sha512_hash (S64 a b c d e f g h) [] =
  BS.concat $ map (toBigEndianBS 64) [a,b,c,d,e,f,g,h]
compute_sha512_hash ins@(S64 a b c d e f g h) (first:rest) =
  compute_sha512_hash next rest
 where
  x = foldl tiny_step512 ins (zip (message_schedule_512 first) sha512_ks)
  S64 a' b' c' d' e' f' g' h' = x
  next = S64 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')

message_schedule_512 :: ByteString -> [Word64]
message_schedule_512 bs = genSched (reverse $ map fromBigEndianBS $ chunk 64 bs)
 where
  genSched curs | length curs == 80 = reverse curs
                | otherwise =
    let sw2  = small_sigma_512_1 $ curs !! 1
        w7   = curs !! 6
        sw15 = small_sigma_512_0 $ curs !! 14
        w16  = curs !! 15
        new_guy = sw2 + w7 + sw15 + w16
    in genSched (new_guy : curs)

tiny_step512 :: State64 -> (Word64, Word64) -> State64
tiny_step512 (S64 a b c d e f g h) (k, w) = S64 a' b' c' d' e' f' g' h'
 where
  a' = t1 + t2
  b' = a
  c' = b
  d' = c
  e' = d + t1
  f' = e
  g' = f
  h' = g
  t1 = h + (big_sigma_512_1 e) + (ch512 e f g) + k + w
  t2 = (big_sigma_512_0 a) + (maj512 a b c)

ch512 :: Word64 -> Word64 -> Word64 -> Word64
ch512 x y z = (x .&. y) `xor` ((complement x) .&. z)

maj512 :: Word64 -> Word64 -> Word64 -> Word64
maj512 x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)

big_sigma_512_0 :: Word64 -> Word64
big_sigma_512_0 x =
  (x `rotate` (-28)) `xor` (x `rotate` (-34)) `xor` (x `rotate` (-39))

big_sigma_512_1 :: Word64 -> Word64
big_sigma_512_1 x =
  (x `rotate` (-14)) `xor` (x `rotate` (-18)) `xor` (x `rotate` (-41))

small_sigma_512_0 :: Word64 -> Word64
small_sigma_512_0 x =
  (x `rotate` (-1)) `xor` (x `rotate` (-8)) `xor` (x `shiftR` 7)

small_sigma_512_1 :: Word64 -> Word64
small_sigma_512_1 x =
  (x `rotate` (-19)) `xor` (x `rotate` (-61)) `xor` (x `shiftR` 6)

sha512_initial_state :: State64
sha512_initial_state =
  S64 0x6a09e667f3bcc908 0xbb67ae8584caa73b 0x3c6ef372fe94f82b 
      0xa54ff53a5f1d36f1 0x510e527fade682d1 0x9b05688c2b3e6c1f 
      0x1f83d9abfb41bd6b 0x5be0cd19137e2179

sha512_ks :: [Word64]
sha512_ks = [
 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
 ]

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

-- --------------------------------------------------------------------------
--
-- INTERNAL ROUTINES
--
-- --------------------------------------------------------------------------

sha_1_256_pad :: ByteString -> ByteString
sha_1_256_pad = generic_pad 448 512 64

sha_384_512_pad :: ByteString -> ByteString
sha_384_512_pad = generic_pad 896 1024 128

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

-- Turn an arbitrary-length message into a set of n-bit long chunks.
chunk :: Int64 -> ByteString -> [ByteString]
chunk sizeBits bs 
  | BS.length bs == 0                = []
  | sizeBits `mod` 8 /= 0             = error "Invalid sizeBits to chunk"
  | BS.length bs `mod` byteSize /= 0 = error "Non-aligned ByteString to chunk"
  | otherwise                        = let (first,rest) = BS.splitAt byteSize bs
                                       in first:(chunk sizeBits rest)
 where byteSize = sizeBits `div` 8

toBigEndianBS :: (Integral a, Bits a) => Int -> a -> ByteString
toBigEndianBS s val = BS.pack $ map getBits [s - 8, s - 16 .. 0]
 where 
   getBits x = fromIntegral $ (val `shiftR` x) .&. 0xFF

fromBigEndianBS :: (Integral a, Bits a) => ByteString -> a
fromBigEndianBS bs = 
  BS.foldl (\ acc x -> (acc `shiftL` 8) + (fromIntegral x)) 0 bs
