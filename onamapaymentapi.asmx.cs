using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Services;
using System.Xml;
using System.Xml.Linq;

namespace OnamaPaymentGateway
{
    /// <summary>
    /// Summary description for onamapaymentapi
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
    // [System.Web.Script.Services.ScriptService]
    public class onamapaymentapi : System.Web.Services.WebService
    {
        UTF8Encoding _encoder = new UTF8Encoding();

        [WebMethod]
        public String HelloWorld()
        {
            return "Hello World";
        }

        /// <summary>
        /// Send hex encoded payload. 
        ///     Method will decode the payload to get XML string, 
        ///     Payload will be digitaly signed & (IV + Signed payload) will be encrypted using symmetric key generated 
        ///     Base64 encode the paylod
        ///     Encrypt the symmetric key using public key & then base64 encode
        ///     Get oAuth token
        ///     Call NEFT API
        ///     Parse the received response and fills the out string parameters
        /// </summary>
        /// <param name="hexString">xml payload encoded in hex</param>
        /// <param name="transactionId">unique alphanumeric string to track the request, the same is used in Inquiry API</param>
        /// <param name="responseStatus">out parameter that will hold the JSON response status value</param>
        /// <param name="responseStr">out parameter that will hold decoded & decrypted returned payload from JSON</param>
        /// <param name="codstatus">out parameter that holds codstatus of 0 if bank accepted the request, else other number</param>
        /// <param name="txtstatus">out parameter that holds text associated with codstatus</param>
        /// <returns>1 = if SUCCESS, 0 = if FAILED with Error</returns>
        [WebMethod]
        public int callNEFTAPI(string hexString, string transactionId, string debuglog,
            string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
            string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
            string canonicalizationmethod, string oauthtokenurl, string nefttransferurl,
            out String responseStatus, out String responseStr, out String codstatus, out String txtstatus)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, nefttransferurl);

            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus = String.Empty;
            txtstatus = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            //XmlDocument xmlBeforeSign = null;
            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "NEFT called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeNEFTXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible payload");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                ////xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());


                WriteToLog(runtimeConfigurations, "Before GenerateSymmetricKey");
                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                WriteToLog(runtimeConfigurations, "Before NewEncryptSignedXML");
                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);

                WriteToLog(runtimeConfigurations, "Before EncodeByteArrayToBase64String");
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                WriteToLog(runtimeConfigurations, "Before NewEncryptionEncodeSymmetricKey");
                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                WriteToLog(runtimeConfigurations, "Before GenerateOAuthToken");
                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call NEFT API
                WriteToLog(runtimeConfigurations, "Before ExecuteTransactionAPI");
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    GetResultsFromNEFTResponse(runtimeConfigurations, responseStr, out codstatus, out txtstatus);
                    WriteToLog(runtimeConfigurations, "CODSTATUS: " + codstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTSTATUS: " + txtstatus, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, "Exception in callNEFTAPI: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                responseStr = "Exception in web method: " + ex.Message;
            }

            //returns 1 if everything wel OK else returns number which is <= 0
            return returnCode;
        }


        /// <summary>
        /// Method to send inquiry payload and receive response from Inquiry API
        ///     accepts hex encoded xml payload
        ///     decode the payload to get XML
        ///     Digitaly signs payload & IV + payload is encrypted using symmetric private key and then Base64 encodes
        ///     SYmmetric key is encrypted using public key and then Base64 encoded
        ///     Generates oAuth token
        ///     Calls Inquiry API
        ///     Parses the response the returns the values from response in out params
        /// </summary>
        /// <param name="hexString">XML payload that is hex encoded</param>
        /// <param name="transactionId">Alphanumeric id used during NEFT API</param>
        /// <param name="responseStatus">Out parameter that holds JSON response status value</param>
        /// <param name="responseStr">Out parameter that holds decoded decrypted response XML</param>
        /// <param name="codstatus">Out parameter that holds value which will tell you if Re-Inquiry is required</param>
        /// <param name="txtreason">Out parameter that holds text reason for the codstatus</param>
        /// <param name="errorcode">Out parameter that holds value from RC node</param>
        /// <param name="errormessage">Out parameter that holds value from RC node</param>
        /// <param name="returncode">Out parameter that holds value from RC node</param>
        /// <returns></returns>
        [WebMethod]
        public int callInquiryAPI(String hexString, string transactionId, string debuglog,
            string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
            string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
            string canonicalizationmethod, string oauthtokenurl, string neftinquiryurl,
                                    out String responseStatus, out String responseStr, out String referenceno, 
                                    out String codstatus1,
                                    out String txtstatus,
                                    out String codstatus2,
                                        out String txtreason, out String errorcode, out String errormessage, out String returncode)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, neftinquiryurl);
            runtimeConfigurations.transactionid = transactionId;

            referenceno = String.Empty;
            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus1 = String.Empty;
            txtstatus = String.Empty;
            codstatus2 = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "Inquiry called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeInquiryXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible input");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                //xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());

                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call NEFT API
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    GetResultsFromInquiryResponse(runtimeConfigurations, responseStr, out referenceno, 
                            out codstatus1, out txtstatus, out codstatus2, out txtreason,
                                                    out errorcode, out errormessage, out returncode);
                    WriteToLog(runtimeConfigurations, "CODSTATUS1: " + codstatus1, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTSTATUS: " + txtstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "CODSTATUS2: " + codstatus2, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTREASON: " + txtreason, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORCODE: " + errorcode, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORMESSAGE: " + errormessage, enforce: true);
                    WriteToLog(runtimeConfigurations, "RETURNCODE: " + returncode, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, ex.Message, enforce: true);
                responseStr = ex.Message;
            }

            //return 1 if everuth went OK, else returns a number which is <= 0
            return returnCode;
        }

        [WebMethod]
        public int callRTGSAPI(string hexString, string transactionId, string debuglog,
                    string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
                    string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
                    string canonicalizationmethod, string oauthtokenurl, string rtgstransferurl,
                    out String responseStatus, out String responseStr, out String codstatus, out String txtstatus)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, rtgstransferurl);

            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus = String.Empty;
            txtstatus = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            //XmlDocument xmlBeforeSign = null;
            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "RTGS called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeRTGSXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible payload");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                ////xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());

                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call NEFT API
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    GetResultsFromNEFTResponse(runtimeConfigurations, responseStr, out codstatus, out txtstatus);
                    WriteToLog(runtimeConfigurations, "CODSTATUS: " + codstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTSTATUS: " + txtstatus, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, ex.Message, enforce: true);
                responseStr = ex.Message;
            }

            //returns 1 if everything wel OK else returns number which is <= 0
            return returnCode;
        }

        [WebMethod]
        public int callRTGSInquiryAPI(String hexString, string transactionId, string debuglog,
                    string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
                    string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
                    string canonicalizationmethod, string oauthtokenurl, string rtgsinquiryurl,
                    out String responseStatus, out String responseStr, out String utr, out String paymentrefno,
                    out String codstatus1, out String txtstatus, out String codstatus2, out String txtreason, 
                    out String errorcode, out String errormessage, out String returncode)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, rtgsinquiryurl);
            runtimeConfigurations.transactionid = transactionId;

            utr = String.Empty;
            paymentrefno = String.Empty;
            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus1 = String.Empty;
            codstatus2 = String.Empty;
            txtstatus = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "RTGS Inquiry called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeInquiryXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible input");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                //xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());

                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call NEFT API
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    //GetResultsFromInquiryResponse(runtimeConfigurations, responseStr, out referenceno, out codstatus, out txtreason,
                    //                                out errorcode, out errormessage, out returncode);

                    GetResultsFromRTGSInquiryResponse(runtimeConfigurations, responseStr,
                            out utr, out paymentrefno, out codstatus1, out txtstatus, out codstatus2,
                            out txtreason, out errorcode, out errormessage, out returncode);
                    WriteToLog(runtimeConfigurations, "CODSTATUS1: " + codstatus1, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTSTATUS: " + txtstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "CODSTATUS2: " + codstatus2, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTREASON: " + txtreason, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORCODE: " + errorcode, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORMESSAGE: " + errormessage, enforce: true);
                    WriteToLog(runtimeConfigurations, "RETURNCODE: " + returncode, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, ex.Message, enforce: true);
                responseStr = ex.Message;
            }

            //return 1 if everuth went OK, else returns a number which is <= 0
            return returnCode;
        }

        [WebMethod]
        public int callA2AAPI(string hexString, string transactionId, string debuglog,
                    string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
                    string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
                    string canonicalizationmethod, string oauthtokenurl, string rtgstransferurl,
                    out String responseStatus, out String responseStr, out String codstatus, out String txtstatus)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, rtgstransferurl);

            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus = String.Empty;
            txtstatus = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            //XmlDocument xmlBeforeSign = null;
            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "A2A called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeA2AXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible payload");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                ////xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());

                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call A2A API
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    GetResultsFromNEFTResponse(runtimeConfigurations, responseStr, out codstatus, out txtstatus);
                    WriteToLog(runtimeConfigurations, "CODSTATUS: " + codstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTSTATUS: " + txtstatus, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, ex.Message, enforce: true);
                responseStr = ex.Message;
            }

            //returns 1 if everything wel OK else returns number which is <= 0
            return returnCode;
        }

        [WebMethod]
        public int callA2AInquiryAPI(String hexString, string transactionId, string debuglog,
                    string pfxcertificatepassword, string pfxcertificatefileName, string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
                    string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
                    string canonicalizationmethod, string oauthtokenurl, string rtgsinquiryurl,
                    out String responseStatus, out String responseStr, out String codstatus, out String txtreason, 
                    out String errorcode, out String errormessage, out String returncode)
        {
            RuntimeConfigurations runtimeConfigurations = LoadConfigurations(transactionId, debuglog, pfxcertificatepassword, pfxcertificatefileName, pemcertificatefileName,
                keyfileName, leafcertificatefileName, clientid, clientsecret, scope, granttype, iduser, groupid, apikey, signaturemethod,
                canonicalizationmethod, oauthtokenurl, rtgsinquiryurl);
            runtimeConfigurations.transactionid = transactionId;

            responseStatus = String.Empty;
            responseStr = String.Empty;
            codstatus = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;

            StringBuilder inputxmlStr = new StringBuilder("");
            StringBuilder compatibleXML = new StringBuilder("");

            XmlDocument xmlAfterSign = null;

            byte[] bytesPrivateEncryptionKey = new byte[32];
            String encodedencryptedPrivateEncryptionKey = String.Empty;
            byte[] encryptedData;
            String encodedData = String.Empty;

            OAuthToken token;

            ResponsePayload responsePayload;
            byte[] decryptedReceivedKey;
            string responseXML = String.Empty;
            int returnCode = 0;

            //int NumberChars = hexString.Length;

            //Since we get String in hex format we use half of its length to convert the String into bytes so that we can get the actual xml
            //byte[] bytes = new byte[NumberChars / 2];

            try
            {
                if (runtimeConfigurations == null)
                    throw new ArgumentException("Not all input parameters were passed");

                WriteToLog(runtimeConfigurations, "A2A Inquiry called at: " + DateTime.Now.ToString(), enforce: true);

                if (String.IsNullOrEmpty(hexString)) throw new ArgumentException("hexString");

                WriteToLog(runtimeConfigurations, "HEX Input");
                WriteToLog(runtimeConfigurations, hexString);

                inputxmlStr.Append(ConvertHexStringToByteToString(hexString));

                WriteToLog(runtimeConfigurations, "Decoded HEX Input");
                WriteToLog(runtimeConfigurations, inputxmlStr.ToString());

                compatibleXML.Append(MakeInquiryXMLCaseCompatible(inputxmlStr.ToString()));
                WriteToLog(runtimeConfigurations, "Compatible input");
                WriteToLog(runtimeConfigurations, compatibleXML.ToString());

                //xmlBeforeSign = new XmlDocument { PreserveWhitespace = true };
                //StringReader stringreader = new StringReader(inputxmlStr);
                //XmlReader xmlreader = XmlReader.Create(stringreader);

                //inputxmlStr = ConvertToLower(xmlreader);

                //digitally sign the xml payload using customers private key
                xmlAfterSign = NewSignPayLoadXML(runtimeConfigurations, compatibleXML.ToString());

                //Now generate 32 byte symmetric private key
                GenerateSymmetricKey(out bytesPrivateEncryptionKey);
                //String encodedPrivateKey = EncodeByteArrayToBase64String(bytesPrivateEncryptionKey);

                //encrypt the signed xml payload
                encryptedData = NewEncryptSignedXML(xmlAfterSign.InnerXml, bytesPrivateEncryptionKey);
                //encode encrypted signed xml payload
                encodedData = EncodeByteArrayToBase64String(encryptedData);

                //encrypt and encode the symmetric private key
                encodedencryptedPrivateEncryptionKey = NewEncryptionEncodeSymmetricKey(runtimeConfigurations, bytesPrivateEncryptionKey);

                //get oauth token
                token = GenerateOAuthToken(runtimeConfigurations);

                //Call NEFT API
                responsePayload = ExecuteTransactionAPI(runtimeConfigurations, encodedData, encodedencryptedPrivateEncryptionKey, token,
                                                string.IsNullOrEmpty(transactionId) ? "1234" : transactionId);

                responseStatus = responsePayload.Status;
                WriteToLog(runtimeConfigurations, "Response Status: " + responseStatus, enforce: true);

                if (responsePayload.Status.ToUpper().Equals("SUCCESS") == true)
                {
                    //decode & decrypt key
                    decryptedReceivedKey = DecryptDecodeReceivedKey(runtimeConfigurations, responsePayload.GWSymmetricKeyEncryptedValue);
                    returnCode = DecryptDecodeReceivedXML(runtimeConfigurations, decryptedReceivedKey, responsePayload.ResponseSignatureEncryptedValue, out responseStr);
                    WriteToLog(runtimeConfigurations, responseStr);
                    //GetResultsFromInquiryResponse(runtimeConfigurations, responseStr, out referenceno, out codstatus, out txtreason,
                    //                                out errorcode, out errormessage, out returncode);

                    GetResultsFromA2AInquiryResponse(runtimeConfigurations, responseStr,
                            out codstatus, out txtreason, out errorcode, out errormessage, out returncode);
                    WriteToLog(runtimeConfigurations, "CODSTATUS: " + codstatus, enforce: true);
                    WriteToLog(runtimeConfigurations, "TXTREASON: " + txtreason, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORCODE: " + errorcode, enforce: true);
                    WriteToLog(runtimeConfigurations, "ERRORMESSAGE: " + errormessage, enforce: true);
                    WriteToLog(runtimeConfigurations, "RETURNCODE: " + returncode, enforce: true);
                }
                else
                {
                    responseStr = responsePayload.Status;
                    returnCode = 0;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(runtimeConfigurations, ex.Message, enforce: true);
                responseStr = ex.Message;
            }

            //return 1 if everuth went OK, else returns a number which is <= 0
            return returnCode;
        }
        public string MakeInquiryXMLCaseCompatible(string inputXML)
        {
            StringBuilder sb = new StringBuilder(inputXML);

            sb = sb.Replace("FAML", "faml");

            sb = sb.Replace("HEADER", "header");
            sb = sb.Replace("EXTSYSNAME", "extsysname");
            sb = sb.Replace("DATPOST", "datpost");
            sb = sb.Replace("BATCHNUMEXT", "batchnumext");
            sb = sb.Replace("IDTXN", "idtxn");
            sb = sb.Replace("IDUSER", "iduser");
            sb = sb.Replace("IDCUST", "idcust");
            sb = sb.Replace("GROUPID", "groupid");
            sb = sb.Replace("INQCOUNT", "inqcount");
            sb = sb.Replace("REQDATETIME", "reqdatetime");

            sb = sb.Replace("INQLIST", "inqlist");
            sb = sb.Replace("PAYMENT>", "payment>");
            sb = sb.Replace("REFERENCENO", "referenceno");
            sb = sb.Replace("PAYMENTREFNO", "paymentrefno");
            sb = sb.Replace("DATPOST", "datpost");
            sb = sb.Replace("DATTXN", "dattxn");

            return sb.ToString();
        }
        public string MakeNEFTXMLCaseCompatible(string inputXML)
        {
            StringBuilder sb = new StringBuilder(inputXML);

            sb = sb.Replace("FAXML", "faxml");


            sb = sb.Replace("HEADER", "header");
            sb = sb.Replace("EXTSYSNAME", "extsysname");
            sb = sb.Replace("DATPOST", "datpost");
            //********************************************************************
            sb = sb.Replace("BATCHNUMEXT", "batchnumext");
            //sb = sb.Replace("0000000077", "000077");
            //*********************************************************************
            sb = sb.Replace("IDTXN", "idtxn");
            sb = sb.Replace("CODCURR", "codcurr");
            sb = sb.Replace("IDUSER", "iduser");
            sb = sb.Replace("IDCUST", "idcust");
            sb = sb.Replace("GROUPID", "groupid");
            sb = sb.Replace("REQDATETIME", "reqdatetime");


            sb = sb.Replace("SUMMARY", "summary");
            sb = sb.Replace("ORGSUMPMT", "orgsumpmt");
            sb = sb.Replace("ORGCOUNTPMT", "orgcountpmt");

            sb = sb.Replace("PAYMENTLIST", "paymentlist");

            sb = sb.Replace("PAYMENT>", "payment>");
            sb = sb.Replace("STANEXT", "stanext");
            sb = sb.Replace("PAYMENTREFNO", "paymentrefno");
            sb = sb.Replace("CUSTID", "CustId");
            sb = sb.Replace("AMOUNT", "Amount");
            sb = sb.Replace("REMITTERNAME", "RemitterName");
            //************************************************************************
            sb = sb.Replace("REMITTERACCOUNT>", "RemitterAccount>");
            //sb = sb.Replace("0010110000182", "000010110000182");
            //************************************************************************
            sb = sb.Replace("REMITTERACCOUNTTYPE", "RemitterAccountType");
            sb = sb.Replace("REMITTER_ADDRESS_1", "Remitter_Address_1");
            sb = sb.Replace("REMITTER_ADDRESS_2", "Remitter_Address_2");
            sb = sb.Replace("REMITTER_ADDRESS_3", "Remitter_Address_3");
            sb = sb.Replace("REMITTER_ADDRESS_4", "Remitter_Address_4");
            sb = sb.Replace("BENEIFSCCODE", "BeneIFSCCODE");
            sb = sb.Replace("BENEACCOUNTTYPE", "BeneAccountType");
            sb = sb.Replace("BENEACCOUNTNUMBER", "BeneAccountNumber");
            sb = sb.Replace("BENENAME", "BeneName");
            sb = sb.Replace("BENEADDRESS_1", "BeneAddress_1");
            sb = sb.Replace("BENEADDRESS_2", "BeneAddress_2");
            sb = sb.Replace("BENEADDRESS_3", "BeneAddress_3");
            sb = sb.Replace("BENEADDRESS_4", "BeneAddress_4");
            sb = sb.Replace("REMITINFORMATION_1", "RemitInformation_1");
            sb = sb.Replace("REMITINFORMATION_2", "RemitInformation_2");
            sb = sb.Replace("REMITINFORMATION_3", "RemitInformation_3");
            sb = sb.Replace("REMITINFORMATION_4", "RemitInformation_4");
            sb = sb.Replace("REMITINFORMATION_5", "RemitInformation_5");
            sb = sb.Replace("REMITINFORMATION_6", "RemitInformation_6");
            sb = sb.Replace("CONTACTDETAILSID", "ContactDetailsID");
            sb = sb.Replace("CONTACTDETAILSDETAIL", "ContactDetailsDETAIL");
            sb = sb.Replace("CODCURR", "codcurr");
            sb = sb.Replace("REFSTAN", "refstan");
            //**************************************************************************
            sb = sb.Replace("FORCEDEBIT", "forcedebit");
            //**************************************************************************
            sb = sb.Replace("TXNDESC", "txndesc");
            sb = sb.Replace("BENEID", "beneid");
            sb = sb.Replace("EMAILID", "emailid");
            sb = sb.Replace("ADVICE1", "advice1");
            sb = sb.Replace("ADVICE2", "advice2");
            sb = sb.Replace("ADVICE3", "advice3");
            sb = sb.Replace("ADVICE4", "advice4");
            sb = sb.Replace("ADVICE5", "advice5");
            sb = sb.Replace("ADVICE6", "advice6");
            sb = sb.Replace("ADVICE7", "advice7");
            sb = sb.Replace("ADVICE8", "advice8");
            sb = sb.Replace("ADVICE9", "advice9");
            sb = sb.Replace("ADVICE10", "advice10");
            sb = sb.Replace("ADDNLFIELD1", "addnlfield1");
            sb = sb.Replace("ADDNLFIELD2", "addnlfield2");
            sb = sb.Replace("ADDNLFIELD3", "addnlfield3");
            sb = sb.Replace("ADDNLFIELD4", "addnlfield4");
            sb = sb.Replace("ADDNLFIELD5", "addnlfield5");

            return sb.ToString();
        }

        public string MakeRTGSXMLCaseCompatible(string inputXML)
        {
            StringBuilder sb = new StringBuilder(inputXML);

            sb = sb.Replace("FAXML", "faxml");


            sb = sb.Replace("HEADER", "header");
            sb = sb.Replace("EXTSYSNAME", "extsysname");
            sb = sb.Replace("DATPOST", "datpost");
            //********************************************************************
            sb = sb.Replace("BATCHNUMEXT", "batchnumext");
            //sb = sb.Replace("0000000077", "000077");
            //*********************************************************************
            sb = sb.Replace("IDTXN", "idtxn");
            sb = sb.Replace("CODCURR", "codcurr");
            sb = sb.Replace("IDUSER", "iduser");
            sb = sb.Replace("IDCUST", "idcust");
            sb = sb.Replace("GROUPID", "groupid");
            sb = sb.Replace("REQDATETIME", "reqdatetime");


            sb = sb.Replace("SUMMARY", "summary");
            sb = sb.Replace("ORGSUMPMT", "orgsumpmt");
            sb = sb.Replace("ORGCOUNTPMT", "orgcountpmt");

            sb = sb.Replace("PAYMENTLIST", "paymentlist");

            sb = sb.Replace("PAYMENT>", "payment>");
            sb = sb.Replace("STANEXT", "stanext");

            //new for rtgs
            sb = sb.Replace("REFSTAN", "refstan");

            sb = sb.Replace("PAYMENTREFNO", "paymentrefno");

            //new for rtgs
            sb = sb.Replace("ACCOUNTTYPE", "accounttype");
            sb = sb.Replace("<ACCOUNTNO", "<accountno");
            sb = sb.Replace("</ACCOUNTNO", "</accountno");
            sb = sb.Replace("IFSCCODE", "ifsccode");
            sb = sb.Replace("TXNDATE", "txndate");


            //new for rtgs
            sb = sb.Replace("AMOUNT", "amount");
            sb = sb.Replace("<CUSTDET>", "<custdet>");
            sb = sb.Replace("</CUSTDET>", "</custdet>");
            sb = sb.Replace("BENEFACCOUNTNO", "benefaccountno");
            sb = sb.Replace("BENEFCUSTDET", "benefcustdet");
            sb = sb.Replace("CUSTUNIQNO", "custuniqno");
            sb = sb.Replace("CUSTDETADD1", "custdetadd1");
            sb = sb.Replace("CUSTDETADD2", "custdetadd2");
            sb = sb.Replace("EXCHGNAM", "exchgnam");
            sb = sb.Replace("CLIENTREFNO", "clientrefno");
            sb = sb.Replace("PAYDETAIL", "paydetail");
            sb = sb.Replace("FORCEDEBIT", "forcedebit");
            sb = sb.Replace("BENEID", "beneid");
            sb = sb.Replace("EMAILID", "emailid");
            sb = sb.Replace("REMITINFORMATION_1", "RemitInformation_1");

            return sb.ToString();
        }

        public string MakeA2AXMLCaseCompatible(string inputXML)
        {
            StringBuilder sb = new StringBuilder(inputXML);

            sb = sb.Replace("FAXML", "faxml");

            sb = sb.Replace("HEADER", "header");
            sb = sb.Replace("EXTSYSNAME", "extsysname");
            sb = sb.Replace("DATPOST", "datpost");
            sb = sb.Replace("BATCHNUMEXT", "batchnumext");
            sb = sb.Replace("IDTXN", "idtxn");
            sb = sb.Replace("CODCURR", "codcurr");
            sb = sb.Replace("IDUSER", "iduser");
            sb = sb.Replace("IDCUST", "idcust");
            sb = sb.Replace("GROUPID", "groupid");
            sb = sb.Replace("REQDATETIME", "reqdatetime");

            sb = sb.Replace("SUMMARY", "summary");
            sb = sb.Replace("ORGCOUNTDR", "orgcountdr");
            sb = sb.Replace("ORGCOUNTCR", "orgcountcr");
            sb = sb.Replace("ORGSUMDR", "orgsumdr");
            sb = sb.Replace("ORGSUMCR", "orgsumcr");
            
            sb = sb.Replace("DEBIT", "debit");
            sb = sb.Replace("STANEXT", "stanext");
            sb = sb.Replace("ACCOUNTNO", "accountno");
            sb = sb.Replace("ORGAMOUNT", "orgamount");
            sb = sb.Replace("TXNDESC", "txndesc");
            sb = sb.Replace("REFERENCENO", "referenceno");

            sb = sb.Replace("CREDITLIST", "creditlist");
            sb = sb.Replace("<CREDIT>", "<credit>");
            sb = sb.Replace("</CREDIT>", "</credit>");
            sb = sb.Replace("<AMOUNT>", "<amount>");
            sb = sb.Replace("</AMOUNT>", "</amount>");
            sb = sb.Replace("TXNDESC", "txndesc");
            sb = sb.Replace("BENEID", "beneid");
            sb = sb.Replace("BENENAME", "BeneName");
            sb = sb.Replace("BENEADDRESS_1", "BeneAddress_1");
            sb = sb.Replace("BENEADDRESS_2", "BeneAddress_2");
            sb = sb.Replace("BENEADDRESS_3", "BeneAddress_3");
            sb = sb.Replace("BENEADDRESS_4", "BeneAddress_4");
            sb = sb.Replace("EMAILID", "emailid");
            return sb.ToString();
        }
        public string ConvertToLower(XmlReader xmlReader)
        {

            XDocument doc = XDocument.Load(xmlReader);
            // also need to change the root element
            doc.Root.Name = doc.Root.Name.LocalName.ToLower();

            foreach (var element in doc.Descendants().Elements())
            {
                element.Name = element.Name.LocalName.ToLower();
            }

            return doc.ToString();
        }


        private string ConvertHexStringToByteToString(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            //for (int i = 0; i < NumberChars; i += 2)
            //    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            UTF8Encoding _encoder = new UTF8Encoding();

            string xmlData = _encoder.GetString(bytes);
            return xmlData;
        }

        public string ConvertStringToHex(string xmlPayload)
        {
            byte[] ba = Encoding.UTF8.GetBytes(xmlPayload);
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public void GetResultsFromNEFTResponse(RuntimeConfigurations cfg, String responseStr, out String codstatus, out String txtstatus)
        {
            XmlDocument doc = new XmlDocument();
            codstatus = String.Empty;
            txtstatus = String.Empty;
            try
            {
                doc.LoadXml(responseStr);
                //int from = responseStr.IndexOf("<codstatus");
                //int len1 = "<codstatus>".Length;
                //int start = from + len1;

                //int to = responseStr.IndexOf("</codstatus");
                //codstatus = responseStr.Substring(start, to);
                XmlNodeList nodeList = doc.DocumentElement.GetElementsByTagName("codstatus");
                if (nodeList.Count > 0)
                {
                    codstatus = nodeList[0].InnerText;
                }

                nodeList = doc.DocumentElement.GetElementsByTagName("txtstatus");
                if (nodeList.Count > 0)
                {
                    txtstatus = nodeList[0].InnerText;
                }
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message, enforce: true);
            }
        }

        public void GetResultsFromInquiryResponse(RuntimeConfigurations cfg, String responseStr, out String referenceno,
                            out String codstatus1,out String txtstatus, out String codstatus2,
                            out String txtreason, out String errorcode, out String errormessage, out String returncode)
        {
            XmlDocument doc = new XmlDocument();
            referenceno = String.Empty;
            codstatus1 = String.Empty;
            txtstatus = String.Empty;
            codstatus2 = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;
            try
            {
                doc.LoadXml(responseStr);
                //int from = responseStr.IndexOf("<codstatus");
                //int len1 = "<codstatus>".Length;
                //int start = from + len1;

                //int to = responseStr.IndexOf("</codstatus");
                //codstatus = responseStr.Substring(start, to);
                XmlNodeList nodeList = null;
                XmlNode childNode = null;

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("codstatus");
                    //if (nodeList.Count > 0)
                    //{
                    //    codstatus = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/header/codstatus");
                    if (childNode != null)
                    {
                        codstatus1 = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting codstatus1: " + ex.Message, enforce: true);
                }
                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("codstatus");
                    //if (nodeList.Count > 0)
                    //{
                    //    codstatus = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/header/txtstatus");
                    if (childNode != null)
                    {
                        txtstatus = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting txtstatus: " + ex.Message, enforce: true);
                }

                try
                {
                    // / faml / inqlist / payment / codstatus
                    // / faml / header / codstatus
                    //nodeList = doc.DocumentElement.GetElementsByTagName("utr");
                    //if (nodeList.Count > 0)
                    //{
                    //    utr = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/codstatus");
                    if (childNode != null)
                    {
                        codstatus2 = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting codstatus2: " + ex.Message, enforce: true);
                }

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("txtreason");
                    //if (nodeList.Count > 0)
                    //{
                    //    txtreason = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/txtreason");
                    if (childNode != null)
                    {
                        txtreason = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting txtreason: " + ex.Message, enforce: true);
                }

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("referenceno");
                    //if (nodeList.Count > 0)
                    //{
                    //    referenceno = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/referenceno");
                    if (childNode != null)
                    {
                        referenceno = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting paymentrefno: " + ex.Message, enforce: true);
                }

                nodeList = doc.DocumentElement.GetElementsByTagName("rc");
                if (nodeList.Count > 0)
                {
                    if (nodeList[0].Attributes.Count > 0)
                    {
                        try
                        {
                            errorcode = nodeList[0].Attributes["errorcode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            errormessage = nodeList[0].Attributes["errormessage"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            returncode = nodeList[0].Attributes["returncode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returncode: " + ex.Message, enforce: true);
                        }
                    }
                    else
                    {
                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errorcode");
                            if (nodeList.Count > 0)
                            {
                                errorcode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errormessage");
                            if (nodeList.Count > 0)
                            {
                                errormessage = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("returnCode");
                            if (nodeList.Count > 0)
                            {
                                returncode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returnCode: " + ex.Message, enforce: true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message, enforce: true);
            }
        }

        public void GetResultsFromRTGSInquiryResponse(RuntimeConfigurations cfg, String responseStr,
                            out String utr, out String paymentrefno, out String codstatus1, out String txtstatus, out String codstatus2,
                            out String txtreason, out String errorcode, out String errormessage, out String returncode)
        {
            XmlDocument doc = new XmlDocument();
            utr = String.Empty;
            paymentrefno = String.Empty;
            codstatus1 = String.Empty;
            txtstatus = String.Empty;
            codstatus2 = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;
            try
            {
                doc.LoadXml(responseStr);
                //int from = responseStr.IndexOf("<codstatus");
                //int len1 = "<codstatus>".Length;
                //int start = from + len1;

                //int to = responseStr.IndexOf("</codstatus");
                //codstatus = responseStr.Substring(start, to);
                XmlNodeList nodeList = null;
                XmlNode childNode = null;
                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("codstatus");
                    //if (nodeList.Count > 0)
                    //{
                    //    codstatus = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/header/codstatus");
                    if (childNode != null)
                    {
                        codstatus1 = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting codstatus1: " + ex.Message, enforce: true);
                }

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("codstatus");
                    //if (nodeList.Count > 0)
                    //{
                    //    codstatus = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/header/txtstatus");
                    if (childNode != null)
                    {
                        txtstatus = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting txtstatus: " + ex.Message, enforce: true);
                }


                try
                {
                    // / faml / inqlist / payment / codstatus
                    // / faml / header / codstatus
                    //nodeList = doc.DocumentElement.GetElementsByTagName("utr");
                    //if (nodeList.Count > 0)
                    //{
                    //    utr = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/codstatus");
                    if (childNode != null)
                    {
                        codstatus2 = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting codstatus2: " + ex.Message, enforce: true);
                }

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("txtreason");
                    //if (nodeList.Count > 0)
                    //{
                    //    txtreason = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/txtreason");
                    if (childNode != null)
                    {
                        txtreason = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting txtreason: " + ex.Message, enforce: true);
                }

                try
                {
                    // / faml / inqlist / payment / codstatus
                    // / faml / header / codstatus
                    //nodeList = doc.DocumentElement.GetElementsByTagName("utr");
                    //if (nodeList.Count > 0)
                    //{
                    //    utr = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/utr");
                    if(childNode != null)
                    {
                        utr = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting utr: " + ex.Message, enforce: true);
                }


                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("referenceno");
                    //if (nodeList.Count > 0)
                    //{
                    //    referenceno = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/paymentrefno");
                    if (childNode != null)
                    {
                        paymentrefno = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting paymentrefno: " + ex.Message, enforce: true);
                }

                nodeList = doc.DocumentElement.GetElementsByTagName("rc");
                if (nodeList.Count > 0)
                {
                    if (nodeList[0].Attributes.Count > 0)
                    {
                        try
                        {
                            errorcode = nodeList[0].Attributes["errorcode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            errormessage = nodeList[0].Attributes["errormessage"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            returncode = nodeList[0].Attributes["returncode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returncode: " + ex.Message, enforce: true);
                        }
                    }
                    else
                    {
                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errorcode");
                            if (nodeList.Count > 0)
                            {
                                errorcode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errormessage");
                            if (nodeList.Count > 0)
                            {
                                errormessage = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("returnCode");
                            if (nodeList.Count > 0)
                            {
                                returncode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returnCode: " + ex.Message, enforce: true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message, enforce: true);
            }
        }

        public void GetResultsFromA2AInquiryResponse(RuntimeConfigurations cfg, String responseStr,
                            out String codstatus, out String txtreason, out String errorcode, out String errormessage, out String returncode)
        {
            XmlDocument doc = new XmlDocument();
            codstatus = String.Empty;
            txtreason = String.Empty;
            errorcode = String.Empty;
            errormessage = String.Empty;
            returncode = String.Empty;
            try
            {
                doc.LoadXml(responseStr);
                //int from = responseStr.IndexOf("<codstatus");
                //int len1 = "<codstatus>".Length;
                //int start = from + len1;

                //int to = responseStr.IndexOf("</codstatus");
                //codstatus = responseStr.Substring(start, to);
                XmlNodeList nodeList = null;
                XmlNode childNode = null;

                try
                {
                    // / faml / inqlist / payment / codstatus
                    // / faml / header / codstatus
                    //nodeList = doc.DocumentElement.GetElementsByTagName("utr");
                    //if (nodeList.Count > 0)
                    //{
                    //    utr = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/codstatus");
                    if (childNode != null)
                    {
                        codstatus = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting codstatus: " + ex.Message, enforce: true);
                }

                try
                {
                    //nodeList = doc.DocumentElement.GetElementsByTagName("txtreason");
                    //if (nodeList.Count > 0)
                    //{
                    //    txtreason = nodeList[0].InnerText;
                    //}
                    childNode = doc.SelectSingleNode("/faml/inqlist/payment/txtreason");
                    if (childNode != null)
                    {
                        txtreason = childNode.InnerText;
                    }
                }
                catch (Exception ex)
                {
                    WriteToLog(cfg, "Error while getting txtreason: " + ex.Message, enforce: true);
                }

                nodeList = doc.DocumentElement.GetElementsByTagName("rc");
                if (nodeList.Count > 0)
                {
                    if (nodeList[0].Attributes.Count > 0)
                    {
                        try
                        {
                            errorcode = nodeList[0].Attributes["errorcode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            errormessage = nodeList[0].Attributes["errormessage"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }
                        try
                        {
                            returncode = nodeList[0].Attributes["returncode"].Value;
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returncode: " + ex.Message, enforce: true);
                        }
                    }
                    else
                    {
                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errorcode");
                            if (nodeList.Count > 0)
                            {
                                errorcode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errorcode: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("errormessage");
                            if (nodeList.Count > 0)
                            {
                                errormessage = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting errormessage: " + ex.Message, enforce: true);
                        }

                        try
                        {
                            nodeList = doc.DocumentElement.GetElementsByTagName("returnCode");
                            if (nodeList.Count > 0)
                            {
                                returncode = nodeList[0].InnerText;
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteToLog(cfg, "Error while getting returnCode: " + ex.Message, enforce: true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message, enforce: true);
            }
        }
        //public async Task WriteToFile(StringBuilder text)
        //{
        //    int timeOut = 100;
        //    Stopwatch stopwatch = new Stopwatch();
        //    stopwatch.Start();
        //    while (true)
        //    {
        //        try
        //        {
        //            //Wait for resource to be free
        //            lock (locker)
        //            {
        //                using (FileStream file = new FileStream(Filepath, FileMode.Append, FileAccess.Write, FileShare.Read))
        //                using (StreamWriter writer = new StreamWriter(file, Encoding.Unicode))
        //                {
        //                    writer.Write(text.ToString());
        //                }
        //            }
        //            break;
        //        }
        //        catch
        //        {
        //            //File not available, conflict with other class instances or application
        //        }
        //        if (stopwatch.ElapsedMilliseconds > timeOut)
        //        {
        //            //Give up.
        //            break;
        //        }
        //        //Wait and Retry
        //        await Task.Delay(5);
        //    }
        //    stopwatch.Stop();
        //}

        public void WriteToLog(RuntimeConfigurations cfg, string msg, bool enforce = false)
        {
            StreamWriter file = null;
            try
            {
                if ((cfg.debuglog == true) || (enforce == true))
                {
                    if (Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "logs\\"))
                    {
                        file = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + "logs\\" + cfg.transactionid + ".txt", append: true, Encoding.UTF8);
                    }
                    else
                    {
                        file = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + cfg.transactionid + ".txt", append: true, Encoding.UTF8);
                    }
                    file.WriteLine(msg);

                }

            }
            catch
            {

            }
            finally
            {
                if (file != null)
                {
                    file.Close();
                }
            }
        }
        public RuntimeConfigurations LoadConfigurations(string transactionid, string debuglog, string pfxcertificatepassword, string pfxcertificatefileName,
            string pemcertificatefileName, string keyfileName, string leafcertificatefileName,
            string clientid, string clientsecret, string scope, string granttype, string iduser, string groupid, string apikey, string signaturemethod,
            string canonicalizationmethod, string oauthtokenurl, string targeturl)
        {
            RuntimeConfigurations runtimeConfigurations = new RuntimeConfigurations();
            //bool bIsUAT = true;
            try
            {
                runtimeConfigurations.transactionid = transactionid;
                try
                {
                    runtimeConfigurations.debuglog = Convert.ToBoolean(debuglog);
                }
                catch
                {
                    runtimeConfigurations.debuglog = false;
                }
                runtimeConfigurations.pfxcertificatepassword = pfxcertificatepassword;
                runtimeConfigurations.pfxcertificatefile = pfxcertificatefileName;
                runtimeConfigurations.pemcertificatefile = pemcertificatefileName;
                runtimeConfigurations.keyfile = keyfileName;
                runtimeConfigurations.leafcertificatefile = leafcertificatefileName;
                runtimeConfigurations.clientid = clientid;
                runtimeConfigurations.clientsecret = clientsecret;
                runtimeConfigurations.scope = scope;
                runtimeConfigurations.granttype = granttype;
                runtimeConfigurations.iduser = iduser;
                runtimeConfigurations.groupid = groupid;
                runtimeConfigurations.apikey = apikey;
                runtimeConfigurations.signaturemethod = signaturemethod;
                runtimeConfigurations.canonicalizationmethod = canonicalizationmethod;
                runtimeConfigurations.oauthtokenurl = oauthtokenurl;
                runtimeConfigurations.targeturl = targeturl;

                //string configFile = AppDomain.CurrentDomain.BaseDirectory + @"configurations.xml";
                //XmlDocument doc = new XmlDocument();
                //doc.Load(configFile);

                //XmlNode appSettingNode = doc.SelectSingleNode("//appSettings");
                //bIsUAT = !Convert.ToBoolean(appSettingNode.Attributes["prod"].Value);

                //XmlNode root = doc.DocumentElement;
                //XmlNode nodeSettings = root.ChildNodes[0];

                //string key = string.Empty;

                ////XmlNodeList nodeList = root.SelectNodes("/configuration/appsettings");
                ////root.ChildNodes[0].ChildNodes[0].Attributes["key"].Value

                //foreach (XmlNode node in nodeSettings.ChildNodes)
                //{
                //    key = node.Attributes["key"].Value;
                //    switch (key)
                //    {
                //        case "rootpath":
                //            if (bIsUAT)
                //                runtimeConfigurations.rootpath = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.rootpath = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "pfxcertificatepassword":
                //            if (bIsUAT)
                //                runtimeConfigurations.pfxcertificatepassword = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.pfxcertificatepassword = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "pfxcertificatefile":
                //            if (bIsUAT)
                //                runtimeConfigurations.pfxcertificatefile = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.pfxcertificatefile = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "pemcertificatefile":
                //            if (bIsUAT)
                //                runtimeConfigurations.pemcertificatefile = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.pemcertificatefile = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "keyfile":
                //            if (bIsUAT)
                //                runtimeConfigurations.keyfile = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.keyfile = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "leafcertificatefile":
                //            if (bIsUAT)
                //                runtimeConfigurations.leafcertificatefile = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.leafcertificatefile = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "logfile":
                //            if (bIsUAT)
                //                runtimeConfigurations.logfile = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.logfile = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "clientid":
                //            if (bIsUAT)
                //                runtimeConfigurations.clientid = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.clientid = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "clientsecret":
                //            if (bIsUAT)
                //                runtimeConfigurations.clientsecret = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.clientsecret = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "scope":
                //            if (bIsUAT)
                //                runtimeConfigurations.scope = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.scope = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "granttype":
                //            if (bIsUAT)
                //                runtimeConfigurations.granttype = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.granttype = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "iduser":
                //            if (bIsUAT)
                //                runtimeConfigurations.iduser = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.iduser = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "groupid":
                //            if (bIsUAT)
                //                runtimeConfigurations.groupid = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.groupid = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "apikey":
                //            if (bIsUAT)
                //                runtimeConfigurations.apikey = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.apikey = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "oauthtokenurl":
                //            if (bIsUAT)
                //                runtimeConfigurations.oauthtokenurl = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.oauthtokenurl = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "nefttransferurl":
                //            if (bIsUAT)
                //                runtimeConfigurations.nefttransferurl = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.nefttransferurl = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "neftinquiryurl":
                //            if (bIsUAT)
                //                runtimeConfigurations.neftinquiryurl = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.neftinquiryurl = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "signaturemethod":
                //            if (bIsUAT)
                //                runtimeConfigurations.signaturemethod = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.signaturemethod = node.Attributes["prodvalue"].Value;
                //            break;
                //        case "canonicalizationmethod":
                //            if (bIsUAT)
                //                runtimeConfigurations.canonicalizationmethod = node.Attributes["uatvalue"].Value;
                //            else
                //                runtimeConfigurations.canonicalizationmethod = node.Attributes["prodvalue"].Value;
                //            break;
                //        default:
                //            break;
                //    }
                //}
            }
            catch
            {
                runtimeConfigurations = null;
            }
            return runtimeConfigurations;
        }
        /// <summary>
        /// Method to decode & decrypt GWSymmetricKeyEncryptedValue received in the response of NEFT API call. 
        /// Following steps need to be doen to get key byte array to be used to decrypt XML payload
        /// a) Base64 decode the Key GWSymmetricKeyEncryptedValue:
        /// b) External partner needs to use the private key of their SSL certificate for decryption.
        /// c) Decrypt the decode value with Partner’s Private key using Algorithm: RSA/ECB/PKCS1Padding
        ///     After decryption, we get the 32 bytes key, which looks like this:OfpBWSiDeP6kIjbyYFDGu3TnBqxTEpLM
        /// d) The above value needs to be used as key for decryption of the tag ResponseSignatureEncryptedValue in Step7
        /// </summary>
        /// <param name="receivedKey"></param>
        /// <returns></returns>
        public byte[] DecryptDecodeReceivedKey(RuntimeConfigurations cfg, string receivedKey)
        {
            byte[] decodedKey = Convert.FromBase64String(receivedKey);

            X509Certificate2 cert = GetCertificateFromPEM_KEY(cfg);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            RSAParameters rsaParam = cert.GetRSAPrivateKey().ExportParameters(true);

            csp.ImportParameters(rsaParam);

            byte[] decryptedKey = csp.Decrypt(decodedKey, false);

            return decryptedKey;
        }

        public string NewDecryptSignedXML(byte[] encryptedString, byte[] encryptionKey)
        {
            using (var provider = new AesCryptoServiceProvider())
            {
                provider.Key = encryptionKey;
                provider.Mode = CipherMode.CBC;
                provider.Padding = PaddingMode.PKCS7;
                using (var ms = new MemoryStream(encryptedString))
                {
                    byte[] buffer = new byte[16];
                    ms.Read(buffer, 0, 16);
                    provider.IV = buffer;
                    using (var decryptor = provider.CreateDecryptor(provider.Key, provider.IV))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            byte[] decrypted = new byte[encryptedString.Length];
                            var byteCount = cs.Read(decrypted, 0, encryptedString.Length);
                            //return Encoding.UTF8.GetString(decrypted, 0, byteCount);
                            return _encoder.GetString(decrypted, 0, byteCount);
                        }
                    }
                }
            }
        }
        public int DecryptDecodeReceivedXML(RuntimeConfigurations cfg, byte[] key, string encodedencryptedXML, out string returnStr)
        {
            returnStr = string.Empty;
            byte[] decodedData = Convert.FromBase64String(encodedencryptedXML);

            string decryptedXML = NewDecryptSignedXML(decodedData, key);

            //first remove <response> tag from xml
            //if (decryptedXML.Contains("<response>"))
            //{
            //    decryptedXML.Replace("<response>", "");
            //}
            //if (decryptedXML.Contains("</response>"))
            //{
            //    decryptedXML.Replace("</response>", "");
            //}

            //Check signature 
            XmlDocument xmlSigndDocument = new XmlDocument();
            xmlSigndDocument.PreserveWhitespace = true;
            xmlSigndDocument.LoadXml(decryptedXML);
            var signedXml = new SignedXml(xmlSigndDocument);
            // double-check the schema
            // usually we would validate using XPath
            XmlNodeList signatureElement = xmlSigndDocument.GetElementsByTagName("Signature");
            if (signatureElement.Count != 1)
            {
                returnStr = "Too many signatures";
                return -1;
            }

            signedXml.LoadXml((XmlElement)signatureElement[0]);

            // validate references here!
            XmlNode faxmlNode;
            if (decryptedXML.Contains("faml"))
            {
                faxmlNode = xmlSigndDocument.SelectSingleNode("//faml");
            }
            else
            {
                faxmlNode = xmlSigndDocument.SelectSingleNode("//faxml");
            }
            string idattrib = "#" + faxmlNode.Attributes["Id"].Value;

            if ((signedXml.SignedInfo.References[0] as Reference)?.Uri != idattrib)
            {
                returnStr = "Check your references!";
                return -2;
            }

            X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + cfg.leafcertificatefile);
            bool isValid = signedXml.CheckSignature(cert, true);

            if (isValid == false)
            {
                returnStr = "Signature verification failed";
                return -3;
            }

            faxmlNode.Attributes.Remove(faxmlNode.Attributes["Id"]);

            returnStr = faxmlNode.OuterXml;

            return 1;
        }
        public String NewEncryptionEncodeSymmetricKey(RuntimeConfigurations cfg, byte[] encryptionKeyBytes)
        {
            X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + cfg.leafcertificatefile);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            RSAParameters rsaParam = cert.GetRSAPublicKey().ExportParameters(false);

            csp.ImportParameters(rsaParam);

            byte[] encryptedKey = csp.Encrypt(encryptionKeyBytes, RSAEncryptionPadding.Pkcs1);

            String encryptedencodedKey = EncodeByteArrayToBase64String(encryptedKey);
            //tbEncodedKey.Text = encryptedencodedKey;

            return encryptedencodedKey;
        }

        /// <summary>
        /// Method to convert byte array to String that is Base64 encoded
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public String EncodeByteArrayToBase64String(byte[] value)
        {
            String encryptedText = Convert.ToBase64String(value);
            return encryptedText;
        }

        /// <summary>
        /// This methd will generate 32 byte private key. Make sure you pass allocated byte array
        /// The same array will be filled with the private key bytes
        /// </summary>
        /// <param name="encryptionKeyBytes"></param>
        public void GenerateSymmetricKey(out byte[] encryptionKeyBytes)
        {
            string stringKey = RandomString(32);
            encryptionKeyBytes = _encoder.GetBytes(stringKey);
        }

        ///// <summary>
        ///// this methid is used to generate ID that is used in faxml and URI tags
        ///// </summary>
        ///// <param name="keySize"></param>
        ///// <returns></returns>
        //public String GenerateAlphaNumericId(int keySize = 32)
        //{
        //    Random random = new Random();
        //    StringBuilder key = new StringBuilder();
        //    while (key.Length < keySize)
        //    {
        //        int character = random.Next(128);
        //        if ((character <= VAR2 && character >= VAR1) || (character <= VAR4 && character >= VAR3) || (character <= NINE && character >= ZERO))
        //        {
        //            key.Append((char)character);
        //        }
        //    }
        //    return key.ToString();
        //}

        private string RandomString(int StringLength)
        {

            Random RNG = new Random();
            int length = StringLength;
            var rString = "";
            for (var i = 0; i < length; i++)
            {
                rString += ((char)(RNG.Next(1, 26) + 64)).ToString().ToLower();
            }
            return rString;
        }

        public X509Certificate2 GetCertificateFromPEM_KEY(RuntimeConfigurations cfg, string pass = "")
        {
            X509Certificate2 certificate = null;
            try
            {
                string pemText = string.Empty;
                string keyText = string.Empty;
                WriteToLog(cfg, "Before reading pem cert file:" + AppDomain.CurrentDomain.BaseDirectory + cfg.pemcertificatefile);
                using (TextReader tr = new StreamReader(AppDomain.CurrentDomain.BaseDirectory + cfg.pemcertificatefile))
                {
                    pemText = tr.ReadToEnd();
                    WriteToLog(cfg, "PEM-TEXT:" + pemText);
                }

                WriteToLog(cfg, "Before reading key file:" + AppDomain.CurrentDomain.BaseDirectory + cfg.keyfile);
                using (TextReader tr = new StreamReader(AppDomain.CurrentDomain.BaseDirectory + cfg.keyfile))
                {
                    keyText = tr.ReadToEnd();
                    WriteToLog(cfg, "KEY-TEXT:" + keyText);
                }
                WriteToLog(cfg, "Before Certificate(pemText, keyText, pass)");
                Certificate cert = new Certificate(pemText, keyText, pass);

                WriteToLog(cfg, "Before cert.GetCertificateFromPEMstring(false)");
                certificate = cert.GetCertificateFromPEMstring(cfg, false);
                WriteToLog(cfg, "End of GetCertificateFromPEM_KEY");
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            WriteToLog(cfg, "Exiting GetCertificateFromPEM_KEY");
            return certificate;
        }
        //public XmlDocument NewSignPayloadXML(XmlDocument xmlBeforeSign)
        //public XmlDocument NewSignPayLoadXML(RuntimeConfigurations cfg, XmlReader xmlReader)
        public XmlDocument NewSignPayLoadXML(RuntimeConfigurations cfg, string inputXml)
        {
            XmlDocument xmlBeforeSign = null;
            try
            //we have to use pfx as the document says the signing needs to happen using partner private key
            {
                //if (xmlReader == null)
                //    throw new ArgumentException(nameof(xmlReader));

                WriteToLog(cfg, "Inside NewSignPayLoadXML");
                xmlBeforeSign = new XmlDocument();// { PreserveWhitespace = false };

                //xmlBeforeSign.Load(xmlReader);
                xmlBeforeSign.LoadXml(inputXml);

                String idString = RandomString(32); //GenerateAlphaNumericId(32);
                //Add the request node as root node
                XmlElement requestAfterElement = xmlBeforeSign.CreateElement("request");

                //Now get the faxml node from beforesignxml to add id attribute as well as signatureElement
                XmlNode faxmlNode = xmlBeforeSign.SelectSingleNode("//faxml");
                if (faxmlNode == null)
                {
                    faxmlNode = xmlBeforeSign.SelectSingleNode("//faml");
                }
                XmlAttribute idAttr = xmlBeforeSign.CreateAttribute("Id");
                idAttr.Value = idString;
                faxmlNode.Attributes.Append(idAttr);

                XmlNodeList nodeList = xmlBeforeSign.GetElementsByTagName("iduser");

                if (nodeList.Count > 0)
                {
                    if (nodeList[0].InnerText.Equals(cfg.iduser) == false)
                    {
                        nodeList[0].InnerText = cfg.iduser;
                    }
                }

                nodeList = xmlBeforeSign.GetElementsByTagName("groupid");

                if (nodeList.Count > 0)
                {
                    if (nodeList[0].InnerText.Equals(cfg.groupid) == false)
                    {
                        nodeList[0].InnerText = cfg.groupid;
                    }
                }

                //add the faxml node to request element
                requestAfterElement.AppendChild(faxmlNode);
                xmlBeforeSign.AppendChild(requestAfterElement);

                WriteToLog(cfg, "Before GetCertificateFromPEM_KEY(cfg)");
                X509Certificate2 cert = GetCertificateFromPEM_KEY(cfg);

                //var rsa = RSA.Create(cert.PrivateKey.KeySize);
                var signedXml = new SignedXml(xmlBeforeSign);

                WriteToLog(cfg, "Before cert.GetRSAPrivateKey()");
                signedXml.SigningKey = cert.GetRSAPrivateKey();

                WriteToLog(cfg, "Before signedXml.Signature");
                Signature XMLSignature = signedXml.Signature;

                signedXml.SignedInfo.SignatureMethod = cfg.signaturemethod; //"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                signedXml.SignedInfo.CanonicalizationMethod = cfg.canonicalizationmethod; //"http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

                var reference = new Reference();
                reference.Uri = "#" + idString;

                //signedXml.AddReference(reference);
                XMLSignature.SignedInfo.AddReference(reference);

                var keyInfo = new KeyInfo();

                WriteToLog(cfg, "Before KeyInfoX509Data(cert)");
                var keyData = new KeyInfoX509Data(cert);
                WriteToLog(cfg, "Adding subjectname: " + cert.SubjectName.Name);
                keyData.AddSubjectName(cert.SubjectName.Name);

                //keyInfo.AddClause(new KeyInfoX509Data(cert));
                keyInfo.AddClause(keyData);

                //signedXml.KeyInfo = keyInfo;
                XMLSignature.KeyInfo = keyInfo;

                WriteToLog(cfg, "Before signedXml.ComputeSignature()");
                signedXml.ComputeSignature();

                XmlElement xmlDigitalSignature = signedXml.GetXml();

                // Append the element to the XML document.
                xmlBeforeSign.DocumentElement.InsertAfter(xmlBeforeSign.ImportNode(xmlDigitalSignature, true), faxmlNode);
                WriteToLog(cfg, "End of NewSignPayLoadXML");
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            WriteToLog(cfg, "Exiting NewSignPayLoadXML xmlBeforeSign= " + xmlBeforeSign.OuterXml);
            return xmlBeforeSign;
        }

        public byte[] NewEncryptSignedXML(String toEncrypt, byte[] key)
        {
            if (String.IsNullOrEmpty(toEncrypt)) throw new ArgumentException("toEncrypt");
            if (key == null || key.Length == 0) throw new ArgumentException("key");
            var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);

            using (var provider = new AesCryptoServiceProvider())
            {
                provider.Key = key;
                //provider.GenerateIV();
                provider.IV = _encoder.GetBytes(RandomString(16));
                provider.Mode = CipherMode.CBC;
                provider.Padding = PaddingMode.PKCS7;
                using (var encryptor = provider.CreateEncryptor(provider.Key, provider.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(provider.IV, 0, 16);
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(toEncryptBytes, 0, toEncryptBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

        }

        public OAuthToken GenerateOAuthToken(RuntimeConfigurations cfg)
        {
            OAuthToken oAuthToken = null;
            try
            {
                WriteToLog(cfg, "Inside GenerateOAuthToken");
                var authenticationString = $"{cfg.clientid}:{cfg.clientsecret}";
                WriteToLog(cfg, "Before EncodeByteArrayToBase64String(_encoder.GetBytes(authenticationString))");
                var base64EncodedAuthenticationString = EncodeByteArrayToBase64String(_encoder.GetBytes(authenticationString));

                WriteToLog(cfg, "Before X509Certificate2: " + AppDomain.CurrentDomain.BaseDirectory + cfg.pfxcertificatefile + Environment.NewLine + cfg.pfxcertificatepassword);
                X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + cfg.pfxcertificatefile, cfg.pfxcertificatepassword);
                HttpClientHandler handler = new HttpClientHandler();
                WriteToLog(cfg, "Before handler.ClientCertificates.Add(cert)");
                handler.ClientCertificates.Add(cert);
                WriteToLog(cfg, "Before new HttpClient(handler)");
                var client = new HttpClient(handler);
                //GetATokenToTestMyRestApiUsingHttpClient(client);
                //return;

                client.DefaultRequestHeaders.Clear();

                var postData = new List<KeyValuePair<String, String>>();

                WriteToLog(cfg, "Before new AuthenticationHeaderValue(\"Basic\", base64EncodedAuthenticationString)");
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
                WriteToLog(cfg, "Before new FormUrlEncodedContent(postData)");
                HttpContent content = new FormUrlEncodedContent(postData);

                WriteToLog(cfg, "Before new MediaTypeHeaderValue(\"application/x-www-form-urlencoded\")");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                WriteToLog(cfg, "Before client.PostAsync: " + cfg.oauthtokenurl + "?" + "grant_type=" + cfg.granttype + "&" + "scope=" + cfg.scope);
                var responseResult = client.PostAsync(cfg.oauthtokenurl + "?" + "grant_type=" + cfg.granttype + "&" + "scope=" + cfg.scope, content).Result;
                if (!responseResult.IsSuccessStatusCode)
                {
                    WriteToLog(cfg, "oAuth URL Failed: " + responseResult.Content.ReadAsStringAsync().Result, enforce: true);
                    throw new HttpRequestException(responseResult.Content.ReadAsStringAsync().Result);
                }
                var jsonContent = responseResult.Content.ReadAsStringAsync().Result;
                oAuthToken = JsonConvert.DeserializeObject<OAuthToken>(jsonContent);
                WriteToLog(cfg, "End of GenerateOAuthToken");
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, "Exception in GenerateOAuthToken: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            WriteToLog(cfg, "Exiting GenerateOAuthToken");
            return oAuthToken;
        }

        public ResponsePayload ExecuteTransactionAPI(RuntimeConfigurations cfg, String encodedData, String encryptedencodedKey,
                                                OAuthToken oAuthToken, string transactionId)
        {
            ResponsePayload responseData = null;

            try
            {
                WriteToLog(cfg, "Inside ExecuteTransactionAPI");

                var requestPayload = new RequestPayload
                {
                    RequestSignatureEncryptedValue = encodedData,
                    SymmetricKeyEncryptedValue = encryptedencodedKey,
                    Scope = cfg.scope,
                    TransactionId = transactionId,
                    OAuthTokenValue = oAuthToken.AccessToken
                };
                // Serialize our concrete class into a JSON String
                var stringPayload = JsonConvert.SerializeObject(requestPayload);

                // Wrap our JSON inside a StringContent which then can be used by the HttpClient class
                //var httpContent = new StringContent(stringPayload, Encoding.ASCII, "application/json");
                var httpContent = new StringContent(stringPayload);
                //httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                WriteToLog(cfg, "Before X509Certificate2: " + AppDomain.CurrentDomain.BaseDirectory + cfg.pfxcertificatefile + Environment.NewLine +  cfg.pfxcertificatepassword);

                X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + cfg.pfxcertificatefile, cfg.pfxcertificatepassword);
                //X509Certificate2 cert = new X509Certificate2(pemcertificateFile);
                HttpClientHandler handler = new HttpClientHandler();
                handler.ClientCertificates.Add(cert);
                var client = new HttpClient(handler);

                client.DefaultRequestHeaders.Add("apikey", cfg.apikey);
                // Do the actual request and await the response
                //var httpResponse = client.PostAsync((bIsNEFT) ? cfg.nefttransferurl : cfg.neftinquiryurl, httpContent).Result;
                WriteToLog(cfg, "Before client.PostAsync: " + cfg.targeturl);
                var httpResponse = client.PostAsync(cfg.targeturl, httpContent).Result;
                // If the response contains content we want to read it!
                if (httpResponse.Content != null)
                {
                    var responseContent = httpResponse.Content.ReadAsStringAsync();

                    // From here on you could deserialize the ResponseContent back again to a concrete C# type using Json.Net
                    var jsonContent = httpResponse.Content.ReadAsStringAsync().Result;
                    WriteToLog(cfg, "Result from API URL: " + jsonContent);
                    responseData = JsonConvert.DeserializeObject<ResponsePayload>(jsonContent);
                }
                WriteToLog(cfg, "End of ExecuteTransactionAPI");
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, "Exception in ExecuteTransactionAPI: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            WriteToLog(cfg, "Exiting ExecuteTransactionAPI");
            return responseData;
        }
    }

    public class OAuthToken
    {
        [JsonProperty("access_token")]
        public String AccessToken { get; set; }

        [JsonProperty("token_type")]
        public String TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("scope")]
        public String Scope { get; set; }
    }

    public class RequestPayload
    {
        public String RequestSignatureEncryptedValue { get; set; }
        public String SymmetricKeyEncryptedValue { get; set; }
        public String Scope { get; set; }
        public String TransactionId { get; set; }
        public String OAuthTokenValue { get; set; }
    }

    public class ResponsePayload
    {
        public String ResponseSignatureEncryptedValue { get; set; }
        public String GWSymmetricKeyEncryptedValue { get; set; }
        public String Scope { get; set; }
        public String TransactionId { get; set; }
        public String Status { get; set; }
    }

    public class RuntimeConfigurations
    {
        public bool debuglog;
        public string transactionid;
        //public String targetserver;
        //public String rootpath;
        public String pfxcertificatepassword;
        public String pfxcertificatefile;
        public String pemcertificatefile;
        public String keyfile;
        public String leafcertificatefile;
        //public String logfile;
        public String clientid;
        public String clientsecret;
        public String scope;
        public String granttype;
        public String iduser;
        public String groupid;
        public String apikey;
        public String oauthtokenurl;
        //public String nefttransferurl;
        //public String neftinquiryurl;
        public string targeturl;
        public string signaturemethod;
        public string canonicalizationmethod;
    }
}
