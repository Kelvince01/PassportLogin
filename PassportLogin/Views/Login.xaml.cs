using System;
using System.Diagnostics;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Navigation;
using PassportLogin.AuthService;
using PassportLogin.Utils;

namespace PassportLogin.Views
{
    public sealed partial class Login : Page
    {
        private UserAccount _account;
        private bool _isExistingLocalAccount;

        public Login()
        {
            this.InitializeComponent();
        }

        protected override async void OnNavigatedTo(NavigationEventArgs e)
        {
            //Check Windows Hello is setup and available on this machine
            if (await MicrosoftPassportHelper.MicrosoftPassportAvailableCheckAsync())
            {
                if (e.Parameter != null)
                {
                    _isExistingLocalAccount = true;
                    //Set the account to the existing account being passed in
                    _account = (UserAccount)e.Parameter;
                    UsernameTextBox.Text = _account.Username;
                    SignInPassportAsync();
                }
            }
        }

        private async void SignInPassportAsync()
        {
            if (_isExistingLocalAccount)
            {
                if (await MicrosoftPassportHelper.GetPassportAuthenticationMessageAsync(_account))
                {
                    Frame.Navigate(typeof(Welcome), _account);
                }
            }
            else if (AuthService.AuthService.Instance.ValidateCredentials(UsernameTextBox.Text, PasswordBox.Password))
            {
                Guid userId = AuthService.AuthService.Instance.GetUserId(UsernameTextBox.Text);

                if (userId != Guid.Empty)
                {
                    //Now that the account exists on server try and create the necessary passport details and add them to the account
                    bool isSuccessful = await MicrosoftPassportHelper.CreatePassportKeyAsync(userId, UsernameTextBox.Text);
                    if (isSuccessful)
                    {
                        Debug.WriteLine("Successfully signed in with Windows Hello!");
                        //Navigate to the Welcome Screen. 
                        _account = AuthService.AuthService.Instance.GetUserAccount(userId);
                        Frame.Navigate(typeof(Welcome), _account);
                    }
                    else
                    {
                        //The passport account creation failed.
                        //Remove the account from the server as passport details were not configured
                        AuthService.AuthService.Instance.PassportRemoveUser(userId);

                        ErrorMessage.Text = "Account Creation Failed";
                    }
                }
            }
            else
            {
                ErrorMessage.Text = "Invalid Credentials";
            }
        }

        private void PassportSignInButton_Click(object sender, RoutedEventArgs e)
        {
            ErrorMessage.Text = "";
            SignInPassportAsync();
        }

        private void RegisterButtonTextBlock_OnPointerPressed(object sender, PointerRoutedEventArgs e)
        {
            ErrorMessage.Text = "";
            Frame.Navigate(typeof(PassportRegister));
        }
    }
}