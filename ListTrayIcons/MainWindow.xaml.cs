using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;

namespace ListTrayIcons
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void ToolBar_Loaded(object sender, RoutedEventArgs e)
        {
            // To hide the annoying arrow at the right of the toolbar
            ToolBar toolBar = (ToolBar)sender;
            var overflowGrid = (FrameworkElement)toolBar.Template.FindName("OverflowGrid", toolBar);
            overflowGrid.Visibility = Visibility.Collapsed;
        }

        private void ExitBtn_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void InfoBtn_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("This app list the task bar icons and info about the process which created them", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                TrayInfoListBox.ItemsSource = IconLister.List();
            }
            catch (Exception ee)
            {
                MessageBox.Show("The following error occured when listing the icons: " + ee, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            switch (e.Key)
            {
                case Key.Escape:
                    ExitBtn_Click(null, null);
                    break;
                case Key.F5:
                    RefreshBtn_Click(null, null);
                    break;
            }
        }
    }
    
    // Represents a single icon and it's info
    public class TrayIconInfo
    {
        public BitmapSource Bitmap { get; set; }
        // PID of the process which created the icon
        public int PID { get; set; }
        // Executable which created the icon
        public string FileName { get; set; }
        public string ToolTip { get; set; }
        public bool IsHidden { get; set; }
    }
}
