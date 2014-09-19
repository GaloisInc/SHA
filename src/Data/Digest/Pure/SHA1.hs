-- |This module exports the core implementation of SHA1. A couple things to
-- note:
--
-- First, please don't use SHA1 for any new algorithms you're using that have
-- any security implications. Any of the SHA2 variants would serve you much
-- better, usually without significant performance cost.
--
-- Second, more simplistic versions of these functions are available in the
-- module Data.Digest.Pure.SHA. If you just want the obvious, ByteString
-- to ByteString sha1 function, you'll find it there.
--
module Data.Digest.Pure.SHA1(
         SHA1State
       , initialSHA1State
       , customSHA1State
       , customSHA1State'
       , advanceSHA1State
       , advanceSHA1State'
       , finalizeSHA1State
       , finalizeSHA1State'
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

-- |In-progress SHA1 state.
data SHA1State  = SHA1S Word64 (Decoder SHA1Values)
data SHA1Values = SHA1V Word32 Word32 Word32 Word32 Word32

-- |Create a new, initial SHA1State for use in building a hash.
initialSHA1State :: SHA1State
initialSHA1State = SHA1S 0 (decoderSHA1 initVals)
 where initVals = SHA1V 0x67452301 0xefcdab89 0x98badcfe 0x10325476 0xc3d2e1f0

-- |Build a new, custom initial SHA1State for use in building a hash. You
-- probably shouldn't do this unless your spec requires it or you've done a lot
-- of deep thinking about hash functions.
customSHA1State :: L.ByteString -> SHA1State
customSHA1State = importSHAState "SHA1" getSHA1State
 where
  getSHA1State =
    do [a, b, c, d, e] <- replicateM 5 getWord32be
       return (SHA1S 0 (Done S.empty 0 (SHA1V a b c d e)))

-- |A variant of 'customSHA1State' that uses strict ByteStrings.
customSHA1State' :: S.ByteString -> SHA1State
customSHA1State' = customSHA1State . L.fromStrict

-- |Add the given ByteString to the ongoing hash.
advanceSHA1State :: SHA1State -> L.ByteString -> SHA1State
advanceSHA1State = advanceLazy advanceSHA1State'

-- |Add the given strict ByteString to the ongoing hash.
advanceSHA1State' :: SHA1State -> S.ByteString -> SHA1State
advanceSHA1State' (SHA1S n decoder) c =
  advanceState SHA1S n c decoderSHA1 decoder

-- |Finalize SHA1State into a lazy ByteString.
finalizeSHA1State :: SHA1State -> L.ByteString
finalizeSHA1State state@(SHA1S n _) =
  let pad                  = generatePad 448 512 n 8
      getValue (SHA1S _ x) = x
      SHA1V a b c d e      = finalState getValue advanceSHA1State state pad
  in runPut $ putWord32be a >> putWord32be b >> putWord32be c >>
              putWord32be d >> putWord32be e

-- |Finalize SHA1State into a strict ByteString.
finalizeSHA1State' :: SHA1State -> S.ByteString
finalizeSHA1State' = L.toStrict . finalizeSHA1State

-- -----------------------------------------------------------------------------
--
-- SHA1 Advancement routine
--
-- -----------------------------------------------------------------------------

decoderSHA1 :: SHA1Values -> Decoder SHA1Values
decoderSHA1 = runGetIncremental . advanceSHA1

advanceSHA1 :: SHA1Values -> Get SHA1Values
advanceSHA1 s00@(SHA1V a00 b00 c00 d00 e00) =
  do w00 <- getWord32be
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
     let w16 = rotateL (w13 `xor` w08 `xor` w02 `xor` w00) 1
         w17 = rotateL (w14 `xor` w09 `xor` w03 `xor` w01) 1
         w18 = rotateL (w15 `xor` w10 `xor` w04 `xor` w02) 1
         w19 = rotateL (w16 `xor` w11 `xor` w05 `xor` w03) 1
         w20 = rotateL (w17 `xor` w12 `xor` w06 `xor` w04) 1
         w21 = rotateL (w18 `xor` w13 `xor` w07 `xor` w05) 1
         w22 = rotateL (w19 `xor` w14 `xor` w08 `xor` w06) 1
         w23 = rotateL (w20 `xor` w15 `xor` w09 `xor` w07) 1
         w24 = rotateL (w21 `xor` w16 `xor` w10 `xor` w08) 1
         w25 = rotateL (w22 `xor` w17 `xor` w11 `xor` w09) 1
         w26 = rotateL (w23 `xor` w18 `xor` w12 `xor` w10) 1
         w27 = rotateL (w24 `xor` w19 `xor` w13 `xor` w11) 1
         w28 = rotateL (w25 `xor` w20 `xor` w14 `xor` w12) 1
         w29 = rotateL (w26 `xor` w21 `xor` w15 `xor` w13) 1
         w30 = rotateL (w27 `xor` w22 `xor` w16 `xor` w14) 1
         w31 = rotateL (w28 `xor` w23 `xor` w17 `xor` w15) 1
         w32 = rotateL (w29 `xor` w24 `xor` w18 `xor` w16) 1
         w33 = rotateL (w30 `xor` w25 `xor` w19 `xor` w17) 1
         w34 = rotateL (w31 `xor` w26 `xor` w20 `xor` w18) 1
         w35 = rotateL (w32 `xor` w27 `xor` w21 `xor` w19) 1
         w36 = rotateL (w33 `xor` w28 `xor` w22 `xor` w20) 1
         w37 = rotateL (w34 `xor` w29 `xor` w23 `xor` w21) 1
         w38 = rotateL (w35 `xor` w30 `xor` w24 `xor` w22) 1
         w39 = rotateL (w36 `xor` w31 `xor` w25 `xor` w23) 1
         w40 = rotateL (w37 `xor` w32 `xor` w26 `xor` w24) 1
         w41 = rotateL (w38 `xor` w33 `xor` w27 `xor` w25) 1
         w42 = rotateL (w39 `xor` w34 `xor` w28 `xor` w26) 1
         w43 = rotateL (w40 `xor` w35 `xor` w29 `xor` w27) 1
         w44 = rotateL (w41 `xor` w36 `xor` w30 `xor` w28) 1
         w45 = rotateL (w42 `xor` w37 `xor` w31 `xor` w29) 1
         w46 = rotateL (w43 `xor` w38 `xor` w32 `xor` w30) 1
         w47 = rotateL (w44 `xor` w39 `xor` w33 `xor` w31) 1
         w48 = rotateL (w45 `xor` w40 `xor` w34 `xor` w32) 1
         w49 = rotateL (w46 `xor` w41 `xor` w35 `xor` w33) 1
         w50 = rotateL (w47 `xor` w42 `xor` w36 `xor` w34) 1
         w51 = rotateL (w48 `xor` w43 `xor` w37 `xor` w35) 1
         w52 = rotateL (w49 `xor` w44 `xor` w38 `xor` w36) 1
         w53 = rotateL (w50 `xor` w45 `xor` w39 `xor` w37) 1
         w54 = rotateL (w51 `xor` w46 `xor` w40 `xor` w38) 1
         w55 = rotateL (w52 `xor` w47 `xor` w41 `xor` w39) 1
         w56 = rotateL (w53 `xor` w48 `xor` w42 `xor` w40) 1
         w57 = rotateL (w54 `xor` w49 `xor` w43 `xor` w41) 1
         w58 = rotateL (w55 `xor` w50 `xor` w44 `xor` w42) 1
         w59 = rotateL (w56 `xor` w51 `xor` w45 `xor` w43) 1
         w60 = rotateL (w57 `xor` w52 `xor` w46 `xor` w44) 1
         w61 = rotateL (w58 `xor` w53 `xor` w47 `xor` w45) 1
         w62 = rotateL (w59 `xor` w54 `xor` w48 `xor` w46) 1
         w63 = rotateL (w60 `xor` w55 `xor` w49 `xor` w47) 1
         w64 = rotateL (w61 `xor` w56 `xor` w50 `xor` w48) 1
         w65 = rotateL (w62 `xor` w57 `xor` w51 `xor` w49) 1
         w66 = rotateL (w63 `xor` w58 `xor` w52 `xor` w50) 1
         w67 = rotateL (w64 `xor` w59 `xor` w53 `xor` w51) 1
         w68 = rotateL (w65 `xor` w60 `xor` w54 `xor` w52) 1
         w69 = rotateL (w66 `xor` w61 `xor` w55 `xor` w53) 1
         w70 = rotateL (w67 `xor` w62 `xor` w56 `xor` w54) 1
         w71 = rotateL (w68 `xor` w63 `xor` w57 `xor` w55) 1
         w72 = rotateL (w69 `xor` w64 `xor` w58 `xor` w56) 1
         w73 = rotateL (w70 `xor` w65 `xor` w59 `xor` w57) 1
         w74 = rotateL (w71 `xor` w66 `xor` w60 `xor` w58) 1
         w75 = rotateL (w72 `xor` w67 `xor` w61 `xor` w59) 1
         w76 = rotateL (w73 `xor` w68 `xor` w62 `xor` w60) 1
         w77 = rotateL (w74 `xor` w69 `xor` w63 `xor` w61) 1
         w78 = rotateL (w75 `xor` w70 `xor` w64 `xor` w62) 1
         w79 = rotateL (w76 `xor` w71 `xor` w65 `xor` w63) 1
         s01 = step1_ch  s00 0x5a827999 w00
         s02 = step1_ch  s01 0x5a827999 w01
         s03 = step1_ch  s02 0x5a827999 w02
         s04 = step1_ch  s03 0x5a827999 w03
         s05 = step1_ch  s04 0x5a827999 w04
         s06 = step1_ch  s05 0x5a827999 w05
         s07 = step1_ch  s06 0x5a827999 w06
         s08 = step1_ch  s07 0x5a827999 w07
         s09 = step1_ch  s08 0x5a827999 w08
         s10 = step1_ch  s09 0x5a827999 w09
         s11 = step1_ch  s10 0x5a827999 w10
         s12 = step1_ch  s11 0x5a827999 w11
         s13 = step1_ch  s12 0x5a827999 w12
         s14 = step1_ch  s13 0x5a827999 w13
         s15 = step1_ch  s14 0x5a827999 w14
         s16 = step1_ch  s15 0x5a827999 w15
         s17 = step1_ch  s16 0x5a827999 w16
         s18 = step1_ch  s17 0x5a827999 w17
         s19 = step1_ch  s18 0x5a827999 w18
         s20 = step1_ch  s19 0x5a827999 w19
         s21 = step1_par s20 0x6ed9eba1 w20
         s22 = step1_par s21 0x6ed9eba1 w21
         s23 = step1_par s22 0x6ed9eba1 w22
         s24 = step1_par s23 0x6ed9eba1 w23
         s25 = step1_par s24 0x6ed9eba1 w24
         s26 = step1_par s25 0x6ed9eba1 w25
         s27 = step1_par s26 0x6ed9eba1 w26
         s28 = step1_par s27 0x6ed9eba1 w27
         s29 = step1_par s28 0x6ed9eba1 w28
         s30 = step1_par s29 0x6ed9eba1 w29
         s31 = step1_par s30 0x6ed9eba1 w30
         s32 = step1_par s31 0x6ed9eba1 w31
         s33 = step1_par s32 0x6ed9eba1 w32
         s34 = step1_par s33 0x6ed9eba1 w33
         s35 = step1_par s34 0x6ed9eba1 w34
         s36 = step1_par s35 0x6ed9eba1 w35
         s37 = step1_par s36 0x6ed9eba1 w36
         s38 = step1_par s37 0x6ed9eba1 w37
         s39 = step1_par s38 0x6ed9eba1 w38
         s40 = step1_par s39 0x6ed9eba1 w39
         s41 = step1_maj s40 0x8f1bbcdc w40
         s42 = step1_maj s41 0x8f1bbcdc w41
         s43 = step1_maj s42 0x8f1bbcdc w42
         s44 = step1_maj s43 0x8f1bbcdc w43
         s45 = step1_maj s44 0x8f1bbcdc w44
         s46 = step1_maj s45 0x8f1bbcdc w45
         s47 = step1_maj s46 0x8f1bbcdc w46
         s48 = step1_maj s47 0x8f1bbcdc w47
         s49 = step1_maj s48 0x8f1bbcdc w48
         s50 = step1_maj s49 0x8f1bbcdc w49
         s51 = step1_maj s50 0x8f1bbcdc w50
         s52 = step1_maj s51 0x8f1bbcdc w51
         s53 = step1_maj s52 0x8f1bbcdc w52
         s54 = step1_maj s53 0x8f1bbcdc w53
         s55 = step1_maj s54 0x8f1bbcdc w54
         s56 = step1_maj s55 0x8f1bbcdc w55
         s57 = step1_maj s56 0x8f1bbcdc w56
         s58 = step1_maj s57 0x8f1bbcdc w57
         s59 = step1_maj s58 0x8f1bbcdc w58
         s60 = step1_maj s59 0x8f1bbcdc w59
         s61 = step1_par s60 0xca62c1d6 w60
         s62 = step1_par s61 0xca62c1d6 w61
         s63 = step1_par s62 0xca62c1d6 w62
         s64 = step1_par s63 0xca62c1d6 w63
         s65 = step1_par s64 0xca62c1d6 w64
         s66 = step1_par s65 0xca62c1d6 w65
         s67 = step1_par s66 0xca62c1d6 w66
         s68 = step1_par s67 0xca62c1d6 w67
         s69 = step1_par s68 0xca62c1d6 w68
         s70 = step1_par s69 0xca62c1d6 w69
         s71 = step1_par s70 0xca62c1d6 w70
         s72 = step1_par s71 0xca62c1d6 w71
         s73 = step1_par s72 0xca62c1d6 w72
         s74 = step1_par s73 0xca62c1d6 w73
         s75 = step1_par s74 0xca62c1d6 w74
         s76 = step1_par s75 0xca62c1d6 w75
         s77 = step1_par s76 0xca62c1d6 w76
         s78 = step1_par s77 0xca62c1d6 w77
         s79 = step1_par s78 0xca62c1d6 w78
         s80 = step1_par s79 0xca62c1d6 w79
         (SHA1V a80 b80 c80 d80 e80) = s80
     return (SHA1V (a00 + a80) (b00 + b80) (c00 + c80) (d00 + d80) (e00 + e80))

step1_ch :: SHA1Values -> Word32 -> Word32 -> SHA1Values
step1_ch (SHA1V a b c d e) k w = (SHA1V a' b' c' d' e')
 where a' = rotateL a 5 + ((b .&. c) `xor` (complement b .&. d)) + e + k + w
       b' = a
       c' = rotateL b 30
       d' = c
       e' = d

step1_par :: SHA1Values -> Word32 -> Word32 -> SHA1Values
step1_par (SHA1V a b c d e) k w = (SHA1V a' b' c' d' e')
 where a' = rotateL a 5 + (b `xor` c `xor` d) + e + k + w
       b' = a
       c' = rotateL b 30
       d' = c
       e' = d

step1_maj :: SHA1Values -> Word32 -> Word32 -> SHA1Values
step1_maj (SHA1V a b c d e) k w = (SHA1V a' b' c' d' e')
 where a' = rotateL a 5 + ((b .&. (c .|. d)) .|. (c .&. d)) + e + k + w
       b' = a
       c' = rotateL b 30
       d' = c
       e' = d
-- See the note on maj, above


