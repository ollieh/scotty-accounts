{-# LANGUAGE OverloadedStrings #-}
import Web.Scotty.Hastache
import Web.Scotty.Trans
import qualified Web.Scotty as WS
import Network.Wai.Middleware.RequestLogger
import Model
import qualified Database.Persist as P
import qualified Database.Persist.Sqlite as S
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as LT
import qualified Crypto.BCrypt as BC
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text.Lazy.Encoding as LT
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Data.Default
import Control.Monad
import qualified Database.Redis as R
import System.Random
import Network.Wai
import Web.Cookie (parseCookies, renderSetCookie, SetCookie(..))
import qualified Blaze.ByteString.Builder as B
import Network.Wai.Session (withSession, Session)
import Network.Wai.Session.Map (mapStore_)
import qualified Data.Vault.Lazy as Vault
import Data.String
import Network.HTTP.Types (ok200)
import Control.Monad.Trans.Resource (ResourceT)
import Network.Wai.Internal (Response(ResponseBuilder,ResponseFile,ResponseSource))
import Network.HTTP.Types (ResponseHeaders)

runDb query = liftIO $ S.runSqlite "db" query

type ActionM = ActionH LT.Text
 
setSessionExpiring :: R.Connection -> ByteString -> Integer -> [(ByteString, ByteString)] -> IO ()
setSessionExpiring conn key timeout values = R.runRedis conn $ do
    R.del [key]
    forM_ values (\x -> R.hset key (fst x) (snd x))
    R.expire key timeout
    return ()

getSession :: R.Connection -> ByteString -> IO (Maybe [(ByteString, ByteString)])
getSession conn key = R.runRedis conn $ do
    result <- R.hgetall key
    let output = case result of
                     (Right b) -> Just b
                     _ -> Nothing
    return output

newKey = do
        let n = 30
        gen <- newStdGen
        let chars = ['0'..'9']++['a'..'z']++['A'..'B']
        let numbers = randomRs (0, (length chars - 1)) gen
        return $ BS.pack $ take n $ map (chars!!) numbers

redisBackend :: R.Connection -> Integer -> Backend
redisBackend conn timeout key = (getSession conn key, setSessionExpiring conn key timeout)

type Backend = ByteString -> (IO (Maybe [(ByteString, ByteString)]), 
    ([(ByteString, ByteString)] -> IO ()))

session :: Backend -> Vault.Key ([(ByteString, ByteString)], 
    ([(ByteString,ByteString)] -> IO ())) -> Middleware
session backend key app req = do
        let msessid = lookup cookieName =<< cookies
        sessid <- liftIO $ case msessid of
                         Nothing -> do
                            newsessid <- newKey
                            return newsessid
                         Just sessid -> do
                            let (bget, bset) = backend sessid
                            msess <- bget
                            newsessid <- case msess of
                                    Just _ -> return sessid
                                    Nothing -> do
                                        newsessid <- newKey
                                        return newsessid
                            return newsessid
        let (bget, bset) = backend sessid
        msess <- bget
        let sess = case msess of
                       Just sess -> sess
                       Nothing -> []
        let newReq = changeRequest sess bset req
        res <- app newReq
        return $ changeResponse sessid res
    where
        cookieName = "sessionid"
        changeRequest :: [(ByteString,ByteString)] -> 
            ([(ByteString,ByteString)] -> IO ()) -> Request -> Request
        changeRequest sess bset req = 
                req {vault = Vault.insert key (sess, bset) (vault req)}
        setCookie = fromString "Set-Cookie"
        ciCookie = fromString "Cookie"
        changeResponse :: ByteString -> Response -> Response
        changeResponse sessid res = mapHeader (\hs -> 
                            (setCookie, newCookie cookieName sessid):hs) res
        cookies = fmap parseCookies $ lookup ciCookie (requestHeaders req)

newCookie cookieName cookieVal = B.toByteString $ 
        renderSetCookie $ def 
                            { setCookieName = cookieName 
                            , setCookieValue = cookieVal
                            }
mapHeader :: (ResponseHeaders -> ResponseHeaders) -> Response -> Response
mapHeader f (ResponseFile s h b1 b2) = ResponseFile s (f h) b1 b2
mapHeader f (ResponseBuilder s h b) = ResponseBuilder s (f h) b
mapHeader f (ResponseSource s h b) = ResponseSource s (f h) b

main :: IO ()
main = scottyH' 3000 $ do
    runDb $ S.runMigration migrateAll
    conn <- liftIO $ R.connect R.defaultConnectInfo
    vaultKey <- liftIO $ Vault.newKey
    middleware $ session (redisBackend conn $ 60*60*2) vaultKey
    setTemplatesDir "templates"
    middleware logStdoutDev
    get "/unauthed" $ html "Unauthed"
    get "/login" $ hastache "login.mustache"
    get "/register" $ hastache "register.mustache"
    post "/register" $ do
            username <- param "username"
            password <- param "password"
            let shortUsername = "Usernames must be at least 4 characters. "
            let shortPassword = "Passwords must be at least 8 characters. " 
            case (4 <= length username, 8 <= length password) of
                (False, False) -> html $ LT.pack $ 
                                    shortPassword ++ shortUsername
                (False, True) -> html $ LT.pack shortUsername
                (True, False) -> html $ LT.pack shortPassword
                _ -> do
                    ment <- runDb $ 
                            P.selectFirst [UserUsername S.==. username] []
                    case ment of
                        Nothing -> do
                            hash <- liftIO $ BC.hashPasswordUsingPolicy 
                                        BC.slowerBcryptHashingPolicy 
                                            {BC.preferredHashCost = 10}
                                        (BS.pack password)
                            userID <- runDb $ P.insert $ User 
                                            username 
                                            (BS.unpack $ fromJust hash)
                            user <- runDb $ P.get userID
                            html $ LT.pack $ show user
                        Just _ -> html "User exists"
    post "/login" $ do
        username <- param "username"
        password <- param "password"
        ment <- runDb $ P.selectFirst [UserUsername S.==. username] []
        let mPasswordsMatch = do
            ent <- ment
            let user = S.entityVal ent
            let username = userUsername user
            let hash = userPassword user
            let passwordsMatch = BC.validatePassword (BS.pack hash) password
            return passwordsMatch
        case mPasswordsMatch of 
                    Just passwordsMatch -> do
                        html $ LT.pack $ show passwordsMatch
                    Nothing -> html "No such user"
    get "/getsession" $ do
        req <- request
        let v = (vault req)
        let Just (sess, hset) = Vault.lookup vaultKey v
        html $ LT.pack $ show sess
    get "/setsession" $ do
        req <- request
        let v = (vault req)
        let Just (sess, hset) = Vault.lookup vaultKey v
        liftIO $ hset [("test","test")]
        html $ "set session"
