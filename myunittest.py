import unittest
from unittest.mock import patch, call
from tkinter import Tk
from datetime import datetime
from antivirus import AntivirusApp

class TestAntivirusApp(unittest.TestCase):
    @patch('antivirus.messagebox.showwarning')
    @patch('antivirus.messagebox.showinfo')
    @patch('antivirus.scrolledtext.ScrolledText.insert')
    @patch('antivirus.AntivirusApp.calculate_file_hash')
    @patch('antivirus.filedialog.askopenfilename')
    def test_scan_file_clean_file(self, mock_askopen, mock_calculate_hash, mock_insert, mock_show_info, mock_show_warning):
        mock_askopen.return_value = '/path/to/clean/file.txt'
        mock_calculate_hash.return_value = '1234567890abcdef'
        root = Tk()
        app = AntivirusApp(root)
        app.browse_file()
        app.scan_file()
        expected_calls = [
            call('/path/to/clean/file.txt'),
            call('1234567890abcdef'),
            call().assert_called_once_with("Clean File", "File is clean and safe."),
            call().assert_called_once_with(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - File: /path/to/clean/file.txt - Hash: 1234567890abcdef\n"),
        ]
        mock_askopen.assert_called_once()
        mock_calculate_hash.assert_called_once_with('/path/to/clean/file.txt')
        print("show_info calls: {}".format(mock_show_info.call_args_list))

if __name__ == "__main__":
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAntivirusApp)
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    print(result)
