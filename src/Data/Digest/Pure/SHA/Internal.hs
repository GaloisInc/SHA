module Data.Digest.Pure.SHA.Internal
 where

import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString      as S
import qualified Data.ByteString.Lazy as L
import           Data.Word

-- |Given a getter that will appropriately read in some SHA state from a
-- bytetring, do so. The first argument is the name of the algorithm, used
-- in error reporting.
importSHAState :: String -> Get a -> L.ByteString -> a
importSHAState name getter inbstr =
  case runGetOrFail getter inbstr of
    Left  (_, _, _) -> error ("Illegal format for custom "++name++" state")
    Right (u, _, x)
      | L.length u > 0 -> error ("Illegal length for custom "++name++" state")
      | otherwise      -> x

-- |Run a decoder until either it fails, ir is in the Partial state, or it is
-- Done with no leftover data to process. The first argument builds the output
-- value when this operation is complete, the second argument creates new
-- Decoders when Done is reached with leftover data, and the final argument is
-- the current decoder.
runHard :: (Decoder a -> b) -> (a -> Decoder a) -> Decoder a -> b
runHard builder newDecoder decoder =
  case decoder of
    Fail _ _ _          -> error "Internal error in SHA"
    Partial _           -> builder decoder
    Done leftover _ vs
      | S.null leftover -> builder decoder
      | otherwise       ->
         let decoder' = pushChunk (newDecoder vs) leftover
         in runHard builder newDecoder decoder'

-- |Given a lazy ByteString (the final argument) and a way to advance the SHA
-- state (the first argument), advance the state across all the chunks in the
-- lazy bytestring.
advanceLazy :: (a -> S.ByteString -> a) -> a -> L.ByteString -> a
advanceLazy strictAdvance st lazyBS = go st (L.toChunks lazyBS)
 where
  go state []       = state
  go state (f:rest) = go (strictAdvance state f) rest

-- |Advance SHA state given a new chunk of data. This should probably be
-- rewritten as a template haskell macro rather than remaining a very
-- silly-looking function.
advanceState :: (Word64 -> Decoder shav -> a) ->
                Word64 -> S.ByteString ->
                (shav -> Decoder shav) ->
                Decoder shav ->
                a
advanceState build n c newDecoder decoder =
  case decoder of
    Fail _ _ _  -> error "Internal error in SHA"
    Partial k   -> runHard (build n') newDecoder (k (Just c))
    Done _ _ vs ->
      case newDecoder vs of
        Fail _ _ _ -> error "Internal error in SHA"
        Done _ _ _ -> error "Internal error (#2) in SHA"
        Partial k  -> runHard (build n') newDecoder (k (Just c))
 where n' = n + fromIntegral (S.length c)

-- |Complete a SHA state to its final value, given its final pad.
finalState :: (a -> Decoder d) -> (b -> c -> a) -> b -> c -> d
finalState getValue advance state pad =
  case getValue (advance state pad) of
    Fail _ _ _  -> error "Internal error generating final hash (#1)."
    Partial _   -> error "Internal error generating final hash (#2)."
    Done _ _ v  -> v

{-# SPECIALIZE ch :: Word32 -> Word32 -> Word32 -> Word32 #-}
{-# SPECIALIZE ch :: Word64 -> Word64 -> Word64 -> Word64 #-}
ch :: Bits a => a -> a -> a -> a
ch x y z = (x .&. y) `xor` (complement x .&. z)

{-# SPECIALIZE maj :: Word32 -> Word32 -> Word32 -> Word32 #-}
{-# SPECIALIZE maj :: Word64 -> Word64 -> Word64 -> Word64 #-}
maj :: Bits a => a -> a -> a -> a
maj x y z = (x .&. (y .|. z)) .|. (y .&. z)
-- note:
--   the original functions is (x & y) ^ (x & z) ^ (y & z)
--   if you fire off truth tables, this is equivalent to 
--     (x & y) | (x & z) | (y & z)
--   which you can the use distribution on:
--     (x & (y | z)) | (y & z)
--   which saves us one operation.

