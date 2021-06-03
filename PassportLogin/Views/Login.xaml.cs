using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using PassportLogin.Models;
using PassportLogin.Utils;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace PassportLogin.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class Login : Page
    {
        private Account _account;
        private bool _isExistingAccount;

        public Login()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// Function called when this frame is navigated to.
        /// Checks to see if Microsoft Passport is available and if an account was passed in.
        /// If an account was passed in set the "_isExistingAccount" flag to true and set the _account
        /// </summary>
        protected override async void OnNavigatedTo(NavigationEventArgs e)
        {
            // Check Microsoft Passport is setup and available on this machine
            if (await MicrosoftPassportHelper.MicrosoftPassportAvailableCheckAsync())
            {
                if (e.Parameter != null)
                {
                    _isExistingAccount = true;
                    // Set the account to the existing account being passed in
                    _account = (Account)e.Parameter;
                    UsernameTextBox.Text = _account.Username;
                    SignInPassport();
                }
            }
            else
            {
                // Microsoft Passport is not setup so inform the user
                PassportStatus.Background = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 50, 170, 207));
                PassportStatusText.Text = "Microsoft Passport is not setup!\n" +
                                          "Please go to Windows Settings and set up a PIN to use it.";
                PassportSignInButton.IsEnabled = false;
            }
        }

        private void PassportSignInButton_Click(object sender, RoutedEventArgs e)
        {
            ErrorMessage.Text = "";
            SignInPassport();
        }

        private void RegisterButtonTextBlock_OnPointerPressed(object sender, PointerRoutedEventArgs e)
        {
            ErrorMessage.Text = "";
            Frame.Navigate(typeof(PassportRegister));
        }

        private async void SignInPassport()
        {
            if (_isExistingAccount)
            {
                if (await MicrosoftPassportHelper.GetPassportAuthenticationMessageAsync(_account))
                {
                    Frame.Navigate(typeof(Welcome), _account);
                }
            }
            else if (AccountHelper.ValidateAccountCredentials(UsernameTextBox.Text))
            {
                //Create and add a new local account
                _account = AccountHelper.AddAccount(UsernameTextBox.Text);
                Debug.WriteLine("Successfully signed in with traditional credentials and created local account instance!");

                if (await MicrosoftPassportHelper.CreatePassportKeyAsync(UsernameTextBox.Text))
                {
                    Debug.WriteLine("Successfully signed in with Microsoft Passport!");
                    Frame.Navigate(typeof(Welcome), _account);
                }
            }
            else
            {
                ErrorMessage.Text = "Invalid Credentials";
            }
        }
    }
}
