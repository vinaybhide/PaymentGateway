using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace OnamaPaymentGateway
{
    public class Certificate
    {
        public Certificate() { }

        public Certificate(string cert, string key, string password)
        {
            this.PublicCertificate = cert;
            this.PrivateKey = key;
            this.Password = password;
        }

        #region Fields
        private string _publicCertificate;
        private string _privateKey;
        private string _password;
        #endregion

        #region Properties
        public string PublicCertificate
        {
            get { return _publicCertificate; }
            set { _publicCertificate = value; }
        }

        public string PrivateKey
        {
            get { return _privateKey; }
            set { _privateKey = value; }
        }

        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }
        #endregion

        public X509Certificate2 GetCertificateFromPEMstring(RuntimeConfigurations cfg, bool certOnly)
        {
            if (certOnly)
                return GetCertificateFromPEMstring(cfg, this.PublicCertificate);
            else
                return GetCertificateFromPEMstring(cfg, this.PublicCertificate, this.PrivateKey, this.Password);
        }

        public static X509Certificate2 GetCertificateFromPEMstring(RuntimeConfigurations cfg, string publicCert)
        {
            return new X509Certificate2(Encoding.UTF8.GetBytes(publicCert));
        }

        public RSACryptoServiceProvider GetPrivateKeyData(RuntimeConfigurations cfg, string privateKey)
        {
            byte[] keyBuffer = Helpers.GetBytesFromPEM(cfg, privateKey, PemStringType.RsaPrivateKey);

            RSACryptoServiceProvider prov = Crypto.DecodeRsaPrivateKey(cfg, keyBuffer);

            return prov;
        }

        public static X509Certificate2 GetCertificateFromPEMstring(RuntimeConfigurations cfg, string publicCert, string privateKey, string password)
        {
            X509Certificate2 certificate = null;
            try
            {
                Helpers.WriteToLog(cfg, "Inside GetCertificateFromPEMstring");

                Helpers.WriteToLog(cfg, "Before Fetching bytes from certificate:" + publicCert);
                byte[] certBuffer = Helpers.GetBytesFromPEM(cfg, publicCert, PemStringType.Certificate);

                Helpers.WriteToLog(cfg, "Before Fetching bytes from key:" + privateKey);
                byte[] keyBuffer = Helpers.GetBytesFromPEM(cfg, privateKey, PemStringType.RsaPrivateKey);

                Helpers.WriteToLog(cfg, "Before new X509Certificate2(certBuffer, password)");
                certificate = new X509Certificate2(certBuffer, password);
                Helpers.WriteToLog(cfg, "Certificate created");

                Helpers.WriteToLog(cfg, "Before Crypto.DecodeRsaPrivateKey(keyBuffer)");
                RSACryptoServiceProvider prov = Crypto.DecodeRsaPrivateKey(cfg, keyBuffer);

                Helpers.WriteToLog(cfg, "Before assigning private key: " + Environment.NewLine + prov.ToXmlString(true));
                certificate.PrivateKey = prov;
                Helpers.WriteToLog(cfg, "After assigning private key: " + Environment.NewLine + certificate.PrivateKey.ToXmlString(true));

                Helpers.WriteToLog(cfg, "End of GetCertificateFromPEMstring");
            }
            catch (Exception ex)
            {
                Helpers.WriteToLog(cfg, "Exception Inside GetCertificateFromPEMstring: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            Helpers.WriteToLog(cfg, "Exiting GetCertificateFromPEMstring");

            return certificate;
        }

    }
}
