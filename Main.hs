import Control.Monad
import Data.Digest.Pure.SHA
import qualified Data.ByteString.Lazy as BS
import System.Directory
import System.Environment
import System.Exit

main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> do
      inconts <- BS.getContents
      putStrLn $ show $ sha384 inconts
      exitSuccess
    xs -> do
      exit_code <- foldM sha384_file ExitSuccess xs
      exitWith exit_code 

sha384_file :: ExitCode -> String -> IO ExitCode
sha384_file prevEC fname = do
  is_file <- doesFileExist fname
  is_dir  <- doesDirectoryExist fname
  case (is_file, is_dir) of
    (False, False) -> do
      putStrLn $ "sha384: " ++ fname ++ ": No such file or directory"
      return $ ExitFailure 22 -- EINVAL
    (False, True)  -> do
      putStrLn $ "sha384: " ++ fname ++ ": Is a directory"
      return $ ExitFailure 22 -- EINVAL
    (True,  _)     -> do
      conts <- BS.readFile fname
      putStrLn $ "sha384 (" ++ fname ++ ") = " ++ show (sha384 conts)
      return $ combineExitCodes prevEC ExitSuccess

combineExitCodes :: ExitCode -> ExitCode -> ExitCode
combineExitCodes ExitSuccess ExitSuccess = ExitSuccess
combineExitCodes _           _           = ExitFailure 22 -- EINVAL
