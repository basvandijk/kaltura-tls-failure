{-# LANGUAGE OverloadedStrings #-}

import           Control.Monad.Trans.Resource
import           Crypto.Cipher.AES128       (AESKey128)
import qualified Crypto.Classes             as Crypto
import qualified Crypto.Hash.SHA1           as SHA1 (hash)
import qualified Crypto.Random              as Crypto
import           Crypto.Random.DRBG         (HashDRBG)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64.URL
import qualified Data.ByteString.Char8      as BC8
import qualified Data.ByteString.Lazy.Char8 as BLC8
import           Data.Default
import qualified Data.Map                   as M (Map, fromList)
import           Data.Monoid
import qualified Data.Serialize             as Serialize
import           Data.Tagged                (witness)
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as TE
import           Data.Time.Clock
import           Data.Time.Clock.POSIX      (utcTimeToPOSIXSeconds)
import qualified Network.HTTP.Conduit       as Http
import           Snap.Core                  (printUrlEncoded)

main :: IO ()
main = do
  let duration    = 60 -- seconds
      sessionType = AdminSession
      partnerId   = "<Your Kaltura partner id>"
      userId      = "<Your Kaltura user id>"
      secret      = "<Your Kaltura secret>"

  gen <- Crypto.newGenIO
  expiryBase <- getCurrentTime
  ks <- newSessionV2 gen expiryBase duration partnerId sessionType userId secret

  mng <- Http.newManager Http.conduitManagerSettings
  addMedia mng ks

-- | Add a Kaltura Media Entry and return the id to it.
--
-- See: http://www.kaltura.com/api_v3/testmeDoc/index.php?service=media&action=add
addMedia :: Http.Manager -> Session -> IO ()
addMedia mng ks = do
    let req = Http.urlEncodedBody
                [ ("ks", TE.encodeUtf8 $ unSession ks)

                , ("entry:mediaType", videoMediaType)
                ]
                (defReq "media" "add")

    resp <- runResourceT $ Http.httpLbs req mng

    BLC8.putStrLn $ Http.responseBody resp

    return ()
  where
    videoMediaType :: B.ByteString
    videoMediaType = "1"

defReq :: B.ByteString -- ^ service
       -> B.ByteString -- ^ action
       -> Http.Request
defReq service action =
    def{ Http.secure      = True
         -- FIXME (BvD): Enabling TLS results in the following exception:
         --
         -- TlsException
         --   (HandshakeFailed
         --     (Error_Misc "<<timeout>>"))
         --
         -- Or:
         --
         -- TlsException
         --   (HandshakeFailed
         --     (Error_Packet_Parsing
         --       "Failed reading: invalid header type:
         --         72\nFrom:\theader\n\n"))

       , Http.host        = "www.kaltura.com"
       , Http.path        = "/api_v3"
       , Http.queryString = "?service=" <> service <>
                            "&action="  <> action  <>
                            "&format=1" -- 1=JSON
       }

-- | A Kaltura Session (KS). A KS is used by Kaltura to authenticate
-- requests.
newtype Session = Session {unSession :: T.Text}
    deriving (Show, Eq, Ord)

-- | The type of Kaltura Session.
--
-- An 'AdminSession' can access all the content of the publisher
-- account and call management APIs, while a 'UserSession' can only
-- access content items owned by the specific user.
data SessionType = AdminSession | UserSession

encodeSessionType :: SessionType -> B.ByteString
encodeSessionType AdminSession = "2"
encodeSessionType UserSession  = "0"

-- | Internally used function for generating Kaltura V2 Session strings.
--
-- See: http://knowledge.kaltura.com/kalturas-api-authentication-and-security
--
-- Also see the generateSessionV2 function in KalturaClient/Client.py
-- in the Kaltura python library.
newSessionV2 :: HashDRBG    -- ^ Random number generator
             -> UTCTime     -- ^ Base time of expiry
             -> Int         -- ^ Session expiry in seconds since the base time
             -> T.Text      -- ^ Partner id
             -> SessionType -- ^ Type of session
             -> T.Text      -- ^ User id
             -> T.Text      -- ^ Secret
             -> IO Session
newSessionV2 gen expiryBase duration partnerId sessionType userId secret = do
    let Right (randomBytes16, _gen') = Crypto.genBytes 16 gen

    let -- Session end time in POSIX seconds
        expiry :: Int
        expiry = floor $ utcTimeToPOSIXSeconds $
                   addUTCTime (fromIntegral duration) expiryBase

        fields :: M.Map B.ByteString [B.ByteString]
        fields = M.fromList
          [ ("_u", [ TE.encodeUtf8 userId ])
          , ("_e", [ BC8.pack $ show expiry ])
          , ("_t", [ encodeSessionType sessionType ])
          ]
        urlEncodedFields = printUrlEncoded fields

        unCheckSummed = randomBytes16 <> urlEncodedFields
        plaintext = SHA1.hash unCheckSummed <> unCheckSummed

        aesKey128 :: AESKey128
        aesKey128 = either error id -- Decoding only fails when the bytestring
                                    -- is shorter than 16 bytes. A SHA1 hash
                                    -- however is 20 bytes so this is always
                                    -- safe.
                  $ Serialize.decode $ SHA1.hash $ TE.encodeUtf8 secret

        n = B.length plaintext
        blkSz = witness Crypto.blockSize aesKey128 `div` 8 -- should be: 16
        justifiedPlaintext
            | n `mod` blkSz == 0 = plaintext
            | otherwise = plaintext <>
                BC8.replicate ((blkSz - n) `mod` blkSz)  '\0'

        (ciphertext, _iv) = Crypto.cbc aesKey128
                                       Crypto.zeroIV
                                       justifiedPlaintext

        decodedKs = "v2|" <> TE.encodeUtf8 partnerId <>
                      "|" <> ciphertext

        encodedKs = Base64.URL.encode decodedKs

    return $ Session $ TE.decodeUtf8 $ encodedKs
