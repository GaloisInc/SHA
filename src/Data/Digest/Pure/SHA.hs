module Data.Digest.Pure.SHA(
         sha1,   sha1Strict,   sha1Lazy
       , sha224, sha224Strict, sha224Lazy
       , sha256, sha256Strict, sha256Lazy
       , sha384, sha384Strict, sha384Lazy
       , sha512, sha512Strict, sha512Lazy
       )
 where

import qualified Data.ByteString      as S
import qualified Data.ByteString.Lazy as L
import Data.Digest.Pure.SHA1
import Data.Digest.Pure.SHA256
import Data.Digest.Pure.SHA512

-- |Compute the SHA1 hash of a lazy ByteString, returning it as a lazy
-- ByteString.
sha1, sha1Lazy :: L.ByteString -> L.ByteString 
sha1 x = finalizeSHA1State (advanceSHA1State initialSHA1State x)
sha1Lazy = sha1

-- |Compute the SHA224 hash of a lazy ByteString, returning it as a lazy
-- ByteString.
sha224, sha224Lazy :: L.ByteString -> L.ByteString
sha224 x = finalizeSHA224State (advanceSHA256State initialSHA224State x)
sha224Lazy = sha224

-- |Compute the SHA256 hash of a lazy ByteString, returning it as a lazy
-- ByteString.
sha256, sha256Lazy :: L.ByteString -> L.ByteString
sha256 x = finalizeSHA256State (advanceSHA256State initialSHA256State x)
sha256Lazy = sha256

-- |Compute the SHA384 hash of a lazy ByteString, returning it as a lazy
-- ByteString.
sha384, sha384Lazy :: L.ByteString -> L.ByteString
sha384 x = finalizeSHA384State (advanceSHA512State initialSHA384State x)
sha384Lazy = sha384

-- |Compute the SHA512 hash of a lazy ByteString, returning it as a lazy
-- ByteString.
sha512, sha512Lazy :: L.ByteString -> L.ByteString
sha512 x = finalizeSHA512State (advanceSHA512State initialSHA512State x)
sha512Lazy = sha512

-- -----------------------------------------------------------------------------

-- |Compute the SHA1 hash of a strict ByteString, returning it as a strict
-- ByteString.
sha1Strict :: S.ByteString -> S.ByteString
sha1Strict x = finalizeSHA1State' (advanceSHA1State' initialSHA1State x)

-- |Compute the SHA224 hash of a strict ByteString, returning it as a strict
-- ByteString.
sha224Strict :: S.ByteString -> S.ByteString
sha224Strict x = finalizeSHA224State' (advanceSHA256State' initialSHA224State x)

-- |Compute the SHA256 hash of a strict ByteString, returning it as a strict
-- ByteString.
sha256Strict :: S.ByteString -> S.ByteString
sha256Strict x = finalizeSHA256State' (advanceSHA256State' initialSHA256State x)

-- |Compute the SHA384 hash of a strict ByteString, returning it as a strict
-- ByteString.
sha384Strict :: S.ByteString -> S.ByteString
sha384Strict x = finalizeSHA384State' (advanceSHA512State' initialSHA384State x)

-- |Compute the SHA512 hash of a strict ByteString, returning it as a strict
-- ByteString.
sha512Strict :: S.ByteString -> S.ByteString
sha512Strict x = finalizeSHA512State' (advanceSHA512State' initialSHA512State x)


