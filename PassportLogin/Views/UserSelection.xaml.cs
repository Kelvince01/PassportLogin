using System.Diagnostics;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using PassportLogin.Models;
using PassportLogin.Utils;

namespace PassportLogin.Views
{
    public sealed partial class UserSelection : Page
    {
        public UserSelection()
        {
            InitializeComponent();
            Loaded += UserSelection_Loaded;
        }

        private void UserSelection_Loaded(object sender, RoutedEventArgs e)
        {
            if (AccountHelper.AccountList.Count == 0)
            {
                //If there are no accounts navigate to the LoginPage
                Frame.Navigate(typeof(Login));
            }


            UserListView.ItemsSource = AccountHelper.AccountList;
            UserListView.SelectionChanged += UserSelectionChanged;
        }

        /// <summary>
        /// Function called when an account is selected in the list of accounts
        /// Navigates to the Login page and passes the chosen account
        /// </summary>
        private void UserSelectionChanged(object sender, RoutedEventArgs e)
        {
            if (((ListView)sender).SelectedValue != null)
            {
                Account account = (Account)((ListView)sender).SelectedValue;
                if (account != null)
                {
                    Debug.WriteLine("Account " + account.Username + " selected!");
                }
                Frame.Navigate(typeof(Login), account);
            }
        }

        /// <summary>
        /// Function called when the "+" button is clicked to add a new user.
        /// Navigates to the Login page with nothing filled out
        /// </summary>
        private void AddUserButton_Click(object sender, RoutedEventArgs e)
        {
            Frame.Navigate(typeof(Login));
        }
    }
}