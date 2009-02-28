import Control.Monad
import Data.Digest.Pure.SHA
import qualified Data.ByteString.Lazy as BS
import System.Directory
import System.Environment
import System.Exit

main :: IO ()
main = do
  bname <- getProgName
  args <- getArgs
  case args of
    [] -> do
      inconts <- BS.getContents
      putStrLn $ show $ ALGORITHM inconts
      exitSuccess
    xs -> do
      exit_code <- foldM (sha_file bname) ExitSuccess xs
      exitWith exit_code 

sha_file :: String -> ExitCode -> String -> IO ExitCode
sha_file bname prevEC fname = do
  is_file <- doesFileExist fname
  is_dir  <- doesDirectoryExist fname
  case (is_file, is_dir) of
    (False, False) -> do
      putStrLn $ bname ++ ": " ++ fname ++ ": No such file or directory"
      return $ ExitFailure 22 -- EINVAL
    (False, True)  -> do
      putStrLn $ bname ++ ": " ++ fname ++ ": Is a directory"
      return $ ExitFailure 22 -- EINVAL
    (True,  _)     -> do
      conts <- BS.readFile fname
      putStrLn $ bname ++ " (" ++ fname ++ ") = " ++ show (ALGORITHM conts)
      return $ combineExitCodes prevEC ExitSuccess

combineExitCodes :: ExitCode -> ExitCode -> ExitCode
combineExitCodes ExitSuccess ExitSuccess = ExitSuccess
combineExitCodes _           _           = ExitFailure 22 -- EINVAL
