using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using BtmI2p.CryptFile.Lib;
using BtmI2p.MiscClientForms;
using BtmI2p.MiscUtils;

namespace BtmI2p.CryptFile.Gui
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public async void ShowErrorMessage(string message, string caption = "Error")
        {
            await MessageBoxAsync.ShowAsync(
                this, message, 
				caption
			);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var encryptedDataText = textBox1.Text;
            if (string.IsNullOrWhiteSpace(encryptedDataText))
            {
                ShowErrorMessage(
                    "IsNullOrWhiteSpace encrypted data"
                );
                return;
            }
            ScryptPassEncryptedData encryptedData;
            try
            {
                 encryptedData = 
                     encryptedDataText.ParseJsonToType<ScryptPassEncryptedData>();
            }
            catch (Exception exc)
            {
                ShowErrorMessage(
                    string.Format(
                        "Parse ScryptPassEncryptedData error {0}", 
                        exc.Message
                    )
                );
                return;
            }
            var passBytes = GetPassBytes();
            byte[] decryptedDataBytes;
            try
            {
                decryptedDataBytes = encryptedData.GetOriginData(passBytes);
            }
            catch (Exception exc)
            {
                ShowErrorMessage(
                    string.Format("Decrypt error: '{0}'", exc.Message));
                return;
            }
            textBox4.Text = Convert.ToBase64String(encryptedData.Salt);
            textBox2.Text = Encoding.UTF8.GetString(decryptedDataBytes);
        }

        private byte[] GetPassBytes()
        {
            return radioButton1.Checked
                ? Encoding.UTF8.GetBytes(textBox3.Text)
                : Convert.FromBase64String(textBox3.Text);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var dataToEncrypt = Encoding.UTF8.GetBytes(textBox2.Text);
            byte[] salt = null;
            if(!string.IsNullOrEmpty(textBox4.Text))
                salt = Convert.FromBase64String(textBox4.Text);
            var passBytes = GetPassBytes();
            textBox1.Text = 
                new ScryptPassEncryptedData
                (
                    dataToEncrypt, 
                    passBytes, 
                    salt
                )
                .WriteObjectToJson();
        }

        private void textBox1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None; 
        }

        private void textBox1_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] fileNames = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (fileNames.Length > 0)
                {
                    string fileName = fileNames[0];
                    textBox5.Text = fileName;
                    textBox1.Text = File.ReadAllText(fileName, Encoding.UTF8);
                }
            }
        }

        private void textBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.A)
            {
                textBox1.SelectAll();
            }
        }

        private void textBox2_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.A)
            {
                textBox2.SelectAll();
            }
        }

        private async void button3_Click(object sender, EventArgs e)
        {
	        try
		    {
			    var scryptEncryptedData = textBox1.Text.ParseJsonToType<ScryptPassEncryptedData>();
			    File.WriteAllText(
				    textBox5.Text,
				    scryptEncryptedData.WriteObjectToJson(),
				    Encoding.UTF8
				    );
		    }
			catch (Exception exc)
		    {
			    await MessageBoxAsync.ShowAsync(this, exc.Message);
		    }
        }
    }
}
