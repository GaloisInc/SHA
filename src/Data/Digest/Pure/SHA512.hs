-- |This module implements the core SHA512 routines: sha384 and sha512.
-- You perform a hash by creating an initial SHA512State, advance it
-- through the ByteString(s) you want to hash, and then finalize it.
--
-- If you'd like a simpler, more straightforward function, you should
-- look at Data.Digest.Pure.SHA.
module Data.Digest.Pure.SHA512(
         SHA512State
       , initialSHA384State
       , initialSHA512State
       , customSHA512State
       , customSHA512State'
       , advanceSHA512State
       , advanceSHA512State'
       , finalizeSHA384State
       , finalizeSHA384State'
       , finalizeSHA512State
       , finalizeSHA512State'
       )
 where

import           Control.Monad
import           Data.Binary.Get
import           Data.Binary.Put
import           Data.Bits
import qualified Data.ByteString      as S
import qualified Data.ByteString.Lazy as L
import           Data.Digest.Pure.SHA.Internal
import           Data.Digest.Pure.SHA.Padding
import           Data.Word

-- |A current SHA384 or SHA512 state in progress.
data SHA512State  = SHA512S Word64 (Decoder SHA512Values)
data SHA512Values = SHA512V !Word64 !Word64 !Word64 !Word64
                            !Word64 !Word64 !Word64 !Word64

-- |The official, initial SHA384 state.
initialSHA384State :: SHA512State
initialSHA384State = SHA512S 0 (decoderSHA512 initVals)
 where initVals = SHA512V 0xcbbb9d5dc1059ed8 0x629a292a367cd507
                          0x9159015a3070dd17 0x152fecd8f70e5939
                          0x67332667ffc00b31 0x8eb44a8768581511
                          0xdb0c2e0d64f98fa7 0x47b5481dbefa4fa4

-- |The official, initial SHA512 state.
initialSHA512State :: SHA512State
initialSHA512State = SHA512S 0 (decoderSHA512 initVals)
 where initVals = SHA512V 0x6a09e667f3bcc908 0xbb67ae8584caa73b
                          0x3c6ef372fe94f82b 0xa54ff53a5f1d36f1
                          0x510e527fade682d1 0x9b05688c2b3e6c1f
                          0x1f83d9abfb41bd6b 0x5be0cd19137e2179

-- |Create a custom initial SHA512 state from the given lazy ByteString.
-- The input should be exactly 64 bytes long.
customSHA512State :: L.ByteString -> SHA512State
customSHA512State = importSHAState "SHA512" getSHA512State
 where
  getSHA512State =
    do [a, b, c, d, e, f, g, h] <- replicateM 8 getWord64be
       return (SHA512S 0 (Done S.empty 0 (SHA512V a b c d e f g h)))

-- |Create a custom initial SHA512 state from the given strict ByteString.
-- The input should be exactly 64 bytes long.
customSHA512State' :: S.ByteString -> SHA512State
customSHA512State' = customSHA512State . L.fromStrict

-- |Advance the hash with the given lazy ByteString.
advanceSHA512State :: SHA512State -> L.ByteString -> SHA512State
advanceSHA512State = advanceLazy advanceSHA512State'

-- |Advance the hash with the given strict ByteString
advanceSHA512State' :: SHA512State -> S.ByteString -> SHA512State
advanceSHA512State' (SHA512S n decoder) c =
  advanceState SHA512S n c decoderSHA512 decoder

-- |Finalize a SHA384 state into a lazy ByteString.
finalizeSHA384State :: SHA512State -> L.ByteString
finalizeSHA384State state@(SHA512S n _) =
  let pad                     = generatePad 896 1024 n 16
      getValue (SHA512S _ x)  = x
      SHA512V a b c d e f _ _ = finalState getValue advanceSHA512State state pad
  in runPut $ putWord64be a >> putWord64be b >> putWord64be c >>
              putWord64be d >> putWord64be e >> putWord64be f

-- |Finalize a SHA384 state into a strict ByteString.
finalizeSHA384State' :: SHA512State -> S.ByteString
finalizeSHA384State' = L.toStrict . finalizeSHA384State

-- |Finalize a SHA512 state into a lazy ByteString.
finalizeSHA512State :: SHA512State -> L.ByteString
finalizeSHA512State state@(SHA512S n _) =
  let pad                     = generatePad 896 1024 n 16
      getValue (SHA512S _ x)  = x
      SHA512V a b c d e f g h = finalState getValue advanceSHA512State state pad
  in runPut $ putWord64be a >> putWord64be b >> putWord64be c >>
              putWord64be d >> putWord64be e >> putWord64be f >>
              putWord64be g >> putWord64be h

-- |Finalize a SHA512 state into a strict ByteString.
finalizeSHA512State' :: SHA512State -> S.ByteString
finalizeSHA512State' = L.toStrict . finalizeSHA512State

-- -----------------------------------------------------------------------------
--
-- SHA512 Advancement routine
--
-- -----------------------------------------------------------------------------

decoderSHA512 :: SHA512Values -> Decoder SHA512Values
decoderSHA512 = runGetIncremental . advanceSHA512

advanceSHA512 :: SHA512Values -> Get SHA512Values
advanceSHA512 s00@(SHA512V a00 b00 c00 d00 e00 f00 g00 h00) =
  do w00 <- getWord64be
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
     let w16 = lsig512_1 w14 + w09 + lsig512_0 w01 + w00
         w17 = lsig512_1 w15 + w10 + lsig512_0 w02 + w01
         w18 = lsig512_1 w16 + w11 + lsig512_0 w03 + w02
         w19 = lsig512_1 w17 + w12 + lsig512_0 w04 + w03
         w20 = lsig512_1 w18 + w13 + lsig512_0 w05 + w04
         w21 = lsig512_1 w19 + w14 + lsig512_0 w06 + w05
         w22 = lsig512_1 w20 + w15 + lsig512_0 w07 + w06
         w23 = lsig512_1 w21 + w16 + lsig512_0 w08 + w07
         w24 = lsig512_1 w22 + w17 + lsig512_0 w09 + w08
         w25 = lsig512_1 w23 + w18 + lsig512_0 w10 + w09
         w26 = lsig512_1 w24 + w19 + lsig512_0 w11 + w10
         w27 = lsig512_1 w25 + w20 + lsig512_0 w12 + w11
         w28 = lsig512_1 w26 + w21 + lsig512_0 w13 + w12
         w29 = lsig512_1 w27 + w22 + lsig512_0 w14 + w13
         w30 = lsig512_1 w28 + w23 + lsig512_0 w15 + w14
         w31 = lsig512_1 w29 + w24 + lsig512_0 w16 + w15
         w32 = lsig512_1 w30 + w25 + lsig512_0 w17 + w16
         w33 = lsig512_1 w31 + w26 + lsig512_0 w18 + w17
         w34 = lsig512_1 w32 + w27 + lsig512_0 w19 + w18
         w35 = lsig512_1 w33 + w28 + lsig512_0 w20 + w19
         w36 = lsig512_1 w34 + w29 + lsig512_0 w21 + w20
         w37 = lsig512_1 w35 + w30 + lsig512_0 w22 + w21
         w38 = lsig512_1 w36 + w31 + lsig512_0 w23 + w22
         w39 = lsig512_1 w37 + w32 + lsig512_0 w24 + w23
         w40 = lsig512_1 w38 + w33 + lsig512_0 w25 + w24
         w41 = lsig512_1 w39 + w34 + lsig512_0 w26 + w25
         w42 = lsig512_1 w40 + w35 + lsig512_0 w27 + w26
         w43 = lsig512_1 w41 + w36 + lsig512_0 w28 + w27
         w44 = lsig512_1 w42 + w37 + lsig512_0 w29 + w28
         w45 = lsig512_1 w43 + w38 + lsig512_0 w30 + w29
         w46 = lsig512_1 w44 + w39 + lsig512_0 w31 + w30
         w47 = lsig512_1 w45 + w40 + lsig512_0 w32 + w31
         w48 = lsig512_1 w46 + w41 + lsig512_0 w33 + w32
         w49 = lsig512_1 w47 + w42 + lsig512_0 w34 + w33
         w50 = lsig512_1 w48 + w43 + lsig512_0 w35 + w34
         w51 = lsig512_1 w49 + w44 + lsig512_0 w36 + w35
         w52 = lsig512_1 w50 + w45 + lsig512_0 w37 + w36
         w53 = lsig512_1 w51 + w46 + lsig512_0 w38 + w37
         w54 = lsig512_1 w52 + w47 + lsig512_0 w39 + w38
         w55 = lsig512_1 w53 + w48 + lsig512_0 w40 + w39
         w56 = lsig512_1 w54 + w49 + lsig512_0 w41 + w40
         w57 = lsig512_1 w55 + w50 + lsig512_0 w42 + w41
         w58 = lsig512_1 w56 + w51 + lsig512_0 w43 + w42
         w59 = lsig512_1 w57 + w52 + lsig512_0 w44 + w43
         w60 = lsig512_1 w58 + w53 + lsig512_0 w45 + w44
         w61 = lsig512_1 w59 + w54 + lsig512_0 w46 + w45
         w62 = lsig512_1 w60 + w55 + lsig512_0 w47 + w46
         w63 = lsig512_1 w61 + w56 + lsig512_0 w48 + w47
         w64 = lsig512_1 w62 + w57 + lsig512_0 w49 + w48
         w65 = lsig512_1 w63 + w58 + lsig512_0 w50 + w49
         w66 = lsig512_1 w64 + w59 + lsig512_0 w51 + w50
         w67 = lsig512_1 w65 + w60 + lsig512_0 w52 + w51
         w68 = lsig512_1 w66 + w61 + lsig512_0 w53 + w52
         w69 = lsig512_1 w67 + w62 + lsig512_0 w54 + w53
         w70 = lsig512_1 w68 + w63 + lsig512_0 w55 + w54
         w71 = lsig512_1 w69 + w64 + lsig512_0 w56 + w55
         w72 = lsig512_1 w70 + w65 + lsig512_0 w57 + w56
         w73 = lsig512_1 w71 + w66 + lsig512_0 w58 + w57
         w74 = lsig512_1 w72 + w67 + lsig512_0 w59 + w58
         w75 = lsig512_1 w73 + w68 + lsig512_0 w60 + w59
         w76 = lsig512_1 w74 + w69 + lsig512_0 w61 + w60
         w77 = lsig512_1 w75 + w70 + lsig512_0 w62 + w61
         w78 = lsig512_1 w76 + w71 + lsig512_0 w63 + w62
         w79 = lsig512_1 w77 + w72 + lsig512_0 w64 + w63
         s01 = step512 s00 0x428a2f98d728ae22 w00
         s02 = step512 s01 0x7137449123ef65cd w01
         s03 = step512 s02 0xb5c0fbcfec4d3b2f w02
         s04 = step512 s03 0xe9b5dba58189dbbc w03
         s05 = step512 s04 0x3956c25bf348b538 w04
         s06 = step512 s05 0x59f111f1b605d019 w05
         s07 = step512 s06 0x923f82a4af194f9b w06
         s08 = step512 s07 0xab1c5ed5da6d8118 w07
         s09 = step512 s08 0xd807aa98a3030242 w08
         s10 = step512 s09 0x12835b0145706fbe w09
         s11 = step512 s10 0x243185be4ee4b28c w10
         s12 = step512 s11 0x550c7dc3d5ffb4e2 w11
         s13 = step512 s12 0x72be5d74f27b896f w12
         s14 = step512 s13 0x80deb1fe3b1696b1 w13
         s15 = step512 s14 0x9bdc06a725c71235 w14
         s16 = step512 s15 0xc19bf174cf692694 w15
         s17 = step512 s16 0xe49b69c19ef14ad2 w16
         s18 = step512 s17 0xefbe4786384f25e3 w17
         s19 = step512 s18 0x0fc19dc68b8cd5b5 w18
         s20 = step512 s19 0x240ca1cc77ac9c65 w19
         s21 = step512 s20 0x2de92c6f592b0275 w20
         s22 = step512 s21 0x4a7484aa6ea6e483 w21
         s23 = step512 s22 0x5cb0a9dcbd41fbd4 w22
         s24 = step512 s23 0x76f988da831153b5 w23
         s25 = step512 s24 0x983e5152ee66dfab w24
         s26 = step512 s25 0xa831c66d2db43210 w25
         s27 = step512 s26 0xb00327c898fb213f w26
         s28 = step512 s27 0xbf597fc7beef0ee4 w27
         s29 = step512 s28 0xc6e00bf33da88fc2 w28
         s30 = step512 s29 0xd5a79147930aa725 w29
         s31 = step512 s30 0x06ca6351e003826f w30
         s32 = step512 s31 0x142929670a0e6e70 w31
         s33 = step512 s32 0x27b70a8546d22ffc w32
         s34 = step512 s33 0x2e1b21385c26c926 w33
         s35 = step512 s34 0x4d2c6dfc5ac42aed w34
         s36 = step512 s35 0x53380d139d95b3df w35
         s37 = step512 s36 0x650a73548baf63de w36
         s38 = step512 s37 0x766a0abb3c77b2a8 w37
         s39 = step512 s38 0x81c2c92e47edaee6 w38
         s40 = step512 s39 0x92722c851482353b w39
         s41 = step512 s40 0xa2bfe8a14cf10364 w40
         s42 = step512 s41 0xa81a664bbc423001 w41
         s43 = step512 s42 0xc24b8b70d0f89791 w42
         s44 = step512 s43 0xc76c51a30654be30 w43
         s45 = step512 s44 0xd192e819d6ef5218 w44
         s46 = step512 s45 0xd69906245565a910 w45
         s47 = step512 s46 0xf40e35855771202a w46
         s48 = step512 s47 0x106aa07032bbd1b8 w47
         s49 = step512 s48 0x19a4c116b8d2d0c8 w48
         s50 = step512 s49 0x1e376c085141ab53 w49
         s51 = step512 s50 0x2748774cdf8eeb99 w50
         s52 = step512 s51 0x34b0bcb5e19b48a8 w51
         s53 = step512 s52 0x391c0cb3c5c95a63 w52
         s54 = step512 s53 0x4ed8aa4ae3418acb w53
         s55 = step512 s54 0x5b9cca4f7763e373 w54
         s56 = step512 s55 0x682e6ff3d6b2b8a3 w55
         s57 = step512 s56 0x748f82ee5defb2fc w56
         s58 = step512 s57 0x78a5636f43172f60 w57
         s59 = step512 s58 0x84c87814a1f0ab72 w58
         s60 = step512 s59 0x8cc702081a6439ec w59
         s61 = step512 s60 0x90befffa23631e28 w60
         s62 = step512 s61 0xa4506cebde82bde9 w61
         s63 = step512 s62 0xbef9a3f7b2c67915 w62
         s64 = step512 s63 0xc67178f2e372532b w63
         s65 = step512 s64 0xca273eceea26619c w64
         s66 = step512 s65 0xd186b8c721c0c207 w65
         s67 = step512 s66 0xeada7dd6cde0eb1e w66
         s68 = step512 s67 0xf57d4f7fee6ed178 w67
         s69 = step512 s68 0x06f067aa72176fba w68
         s70 = step512 s69 0x0a637dc5a2c898a6 w69
         s71 = step512 s70 0x113f9804bef90dae w70
         s72 = step512 s71 0x1b710b35131c471b w71
         s73 = step512 s72 0x28db77f523047d84 w72
         s74 = step512 s73 0x32caab7b40c72493 w73
         s75 = step512 s74 0x3c9ebe0a15c9bebc w74
         s76 = step512 s75 0x431d67c49c100d4c w75
         s77 = step512 s76 0x4cc5d4becb3e42b6 w76
         s78 = step512 s77 0x597f299cfc657e2a w77
         s79 = step512 s78 0x5fcb6fab3ad6faec w78
         s80 = step512 s79 0x6c44198c4a475817 w79
         SHA512V a80 b80 c80 d80 e80 f80 g80 h80 = s80
     return $ SHA512V (a00 + a80) (b00 + b80) (c00 + c80) (d00 + d80)
                      (e00 + e80) (f00 + f80) (g00 + g80) (h00 + h80)

step512 :: SHA512Values -> Word64 -> Word64 -> SHA512Values
step512 (SHA512V a b c d e f g h) k w = SHA512V a' b' c' d' e' f' g' h'
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

bsig512_0 :: Word64 -> Word64
bsig512_0 x = rotateR x 28 `xor` rotateR x 34 `xor` rotateR x 39

bsig512_1 :: Word64 -> Word64
bsig512_1 x = rotateR x 14 `xor` rotateR x 18 `xor` rotateR x 41

lsig512_0 :: Word64 -> Word64
lsig512_0 x = rotateR x 1 `xor` rotateR x 8 `xor` shiftR x 7

lsig512_1 :: Word64 -> Word64
lsig512_1 x = rotateR x 19 `xor` rotateR x 61 `xor` shiftR x 6


