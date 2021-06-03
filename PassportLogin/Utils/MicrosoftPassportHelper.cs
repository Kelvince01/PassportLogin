using System;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Storage.Streams;
using PassportLogin.AuthService;
using PassportLogin.Models;

namespace PassportLogin.Utils
{
    public static class MicrosoftPassportHelper
    {
        public static async Task<bool> CreatePassportKeyAsync(Guid userId, string username)
        {
            KeyCredentialRetrievalResult keyCreationResult = await KeyCredentialManager.RequestCreateAsync(username, KeyCredentialCreationOption.ReplaceExisting);

            switch (keyCreationResult.Status)
            {
                case KeyCredentialStatus.Success:
                    Debug.WriteLine("Successfully made key");
                    await GetKeyAttestationAsync(userId, keyCreationResult);
                    return true;
                case KeyCredentialStatus.UserCanceled:
                    Debug.WriteLine("User cancelled sign-in process.");
                    break;
                case KeyCredentialStatus.NotFound:
                    // User needs to setup Windows Hello
                    Debug.WriteLine("Windows Hello is not setup!\nPlease go to Windows Settings and set up a PIN to use it.");
                    break;
                default:
                    break;
            }

            return false;
        }

        private static async Task GetKeyAttestationAsync(Guid userId, KeyCredentialRetrievalResult keyCreationResult)
        {
            KeyCredential userKey = keyCreationResult.Credential;
            IBuffer publicKey = userKey.RetrievePublicKey();
            KeyCredentialAttestationResult keyAttestationResult = await userKey.GetAttestationAsync();
            IBuffer keyAttestation = null;
            IBuffer certificateChain = null;
            bool keyAttestationIncluded = false;
            bool keyAttestationCanBeRetrievedLater = false;
            KeyCredentialAttestationStatus keyAttestationRetryType = 0;

            if (keyAttestationResult.Status == KeyCredentialAttestationStatus.Success)
            {
                keyAttestationIncluded = true;
                keyAttestation = keyAttestationResult.AttestationBuffer;
                certificateChain = keyAttestationResult.CertificateChainBuffer;
                Debug.WriteLine("Successfully made key and attestation");
            }
            else if (keyAttestationResult.Status == KeyCredentialAttestationStatus.TemporaryFailure)
            {
                keyAttestationRetryType = KeyCredentialAttestationStatus.TemporaryFailure;
                keyAttestationCanBeRetrievedLater = true;
                Debug.WriteLine("Successfully made key but not attestation");
            }
            else if (keyAttestationResult.Status == KeyCredentialAttestationStatus.NotSupported)
            {
                keyAttestationRetryType = KeyCredentialAttestationStatus.NotSupported;
                keyAttestationCanBeRetrievedLater = false;
                Debug.WriteLine("Key created, but key attestation not supported");
            }

            Guid deviceId = Helpers.GetDeviceId();
            //Update the Pasport details with the information we have just gotten above.
            UpdatePassportDetails(userId, deviceId, publicKey.ToArray(), keyAttestationResult);
        }

        public static bool UpdatePassportDetails(Guid userId, Guid deviceId, byte[] publicKey, KeyCredentialAttestationResult keyAttestationResult)
        {
            //In the real world you would use an API to add Passport signing info to server for the signed in _account.
            //For this tutorial we do not implement a WebAPI for our server and simply mock the server locally 
            //The CreatePassportKey method handles adding the Windows Hello account locally to the device using the KeyCredential Manager

            //Using the userId the existing account should be found and updated.
            AuthService.AuthService.Instance.PassportUpdateDetails(userId, deviceId, publicKey, keyAttestationResult);
            return true;
        }

        public static async void RemovePassportAccountAsync(UserAccount account)
        {
            //Open the account with Windows Hello
            KeyCredentialRetrievalResult keyOpenResult = await KeyCredentialManager.OpenAsync(account.Username);

            if (keyOpenResult.Status == KeyCredentialStatus.Success)
            {
                // In the real world you would send key information to server to unregister
                AuthService.AuthService.Instance.PassportRemoveUser(account.UserId);
            }

            //Then delete the account from the machines list of Passport Accounts
            await KeyCredentialManager.DeleteAsync(account.Username);
        }

        private static async Task<bool> RequestSignAsync(Guid userId, KeyCredentialRetrievalResult openKeyResult)
        {
            // Calling userKey.RequestSignAsync() prompts the uses to enter the PIN or use Biometrics (Windows Hello).
            // The app would use the private key from the user account to sign the sign-in request (challenge)
            // The client would then send it back to the server and await the servers response.
            IBuffer challengeMessage = AuthService.AuthService.Instance.PassportRequestChallenge();
            KeyCredential userKey = openKeyResult.Credential;
            KeyCredentialOperationResult signResult = await userKey.RequestSignAsync(challengeMessage);

            if (signResult.Status == KeyCredentialStatus.Success)
            {
                // If the challenge from the server is signed successfully
                // send the signed challenge back to the server and await the servers response
                return AuthService.AuthService.Instance.SendServerSignedChallenge(
                    userId, Helpers.GetDeviceId(), signResult.Result.ToArray());
            }
            else if (signResult.Status == KeyCredentialStatus.UserCanceled)
            {
                // User cancelled the Windows Hello PIN entry.
            }
            else if (signResult.Status == KeyCredentialStatus.NotFound)
            {
                // Must recreate Windows Hello key
            }
            else if (signResult.Status == KeyCredentialStatus.SecurityDeviceLocked)
            {
                // Can't use Windows Hello right now, remember that hardware failed and suggest restart
            }
            else if (signResult.Status == KeyCredentialStatus.UnknownError)
            {
                // Can't use Windows Hello right now, try again later
            }

            return false;
        }

        public static async Task<bool> GetPassportAuthenticationMessageAsync(UserAccount account)
        {
            KeyCredentialRetrievalResult openKeyResult = await KeyCredentialManager.OpenAsync(account.Username);
            //Calling OpenAsync will allow the user access to what is available in the app and will not require user credentials again.
            //If you wanted to force the user to sign in again you can use the following:
            //var consentResult = await Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync(account.Username);
            //This will ask for the either the password of the currently signed in Microsoft Account or the PIN used for Windows Hello.

            if (openKeyResult.Status == KeyCredentialStatus.Success)
            {
                //If OpenAsync has succeeded, the next thing to think about is whether the client application requires access to backend services.
                //If it does here you would Request a challenge from the Server. The client would sign this challenge and the server
                //would check the signed challenge. If it is correct it would allow the user access to the backend.
                //You would likely make a new method called RequestSignAsync to handle all this
                //for example, RequestSignAsync(openKeyResult);
                //Refer to the second Windows Hello sample for information on how to do this.

                //For this sample there is not concept of a server implemented so just return true.
                return await RequestSignAsync(account.UserId, openKeyResult);
            }
            else if (openKeyResult.Status == KeyCredentialStatus.NotFound)
            {
                //If the _account is not found at this stage. It could be one of two errors. 
                //1. Windows Hello has been disabled
                //2. Windows Hello has been disabled and re-enabled cause the Windows Hello Key to change.
                //Calling CreatePassportKey and passing through the account will attempt to replace the existing Windows Hello Key for that account.
                //If the error really is that Windows Hello is disabled then the CreatePassportKey method will output that error.
                if (await CreatePassportKeyAsync(account.UserId, account.Username))
                {
                    //If the Passport Key was again successfully created, Windows Hello has just been reset.
                    //Now that the Passport Key has been reset for the _account retry sign in.
                    return await GetPassportAuthenticationMessageAsync(account);
                }
            }

            // Can't use Passport right now, try again later
            return false;
        }

        /// <summary>
        /// Checks to see if Passport is ready to be used.
        /// 
        /// Passport has dependencies on:
        ///     1. Having a connected Microsoft Account
        ///     2. Having a Windows PIN set up for that _account on the local machine
        /// </summary>
        public static async Task<bool> MicrosoftPassportAvailableCheckAsync()
        {
            bool keyCredentialAvailable = await KeyCredentialManager.IsSupportedAsync();
            if (keyCredentialAvailable == false)
            {
                // Key credential is not enabled yet as user 
                // needs to connect to a Microsoft Account and select a PIN in the connecting flow.
                Debug.WriteLine("Microsoft Passport is not setup!\nPlease go to Windows Settings and set up a PIN to use it.");
                return false;
            }

            return true;
        }

        public static void RemovePassportDevice(UserAccount account, Guid deviceId)
        {
            AuthService.AuthService.Instance.PassportRemoveDevice(account.UserId, deviceId);
        }
    }
}