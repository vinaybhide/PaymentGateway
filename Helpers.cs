using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace OnamaPaymentGateway
{
    public class Helpers
    {
        /// <summary>
        /// This helper function parses an integer size from the reader using the ASN.1 format
        /// </summary>
        /// <param name="rd"></param>
        /// <returns></returns>
        public static int DecodeIntegerSize(RuntimeConfigurations cfg, System.IO.BinaryReader rd)
        {
            byte byteValue;
            int count;
            try
            {
                Helpers.WriteToLog(cfg, "Inside DecodeIntegerSize");

                byteValue = rd.ReadByte();
                if (byteValue != 0x02)        // indicates an ASN.1 integer value follows
                {
                    Helpers.WriteToLog(cfg, "byteValue != 0x02, indicates an ASN.1 integer value follows. Returning 0");
                    return 0;
                }
                byteValue = rd.ReadByte();
                if (byteValue == 0x81)
                {
                    Helpers.WriteToLog(cfg, "byteValue == 0x81, data size is the following byte");

                    count = rd.ReadByte();    // data size is the following byte

                    Helpers.WriteToLog(cfg, "byteValue == 0x81, count= " + count.ToString());

                }
                else if (byteValue == 0x82)
                {
                    Helpers.WriteToLog(cfg, "byteValue == 0x82, data size in next 2 bytes");
                    byte hi = rd.ReadByte();  // data size in next 2 bytes
                    byte lo = rd.ReadByte();
                    count = BitConverter.ToUInt16(new[] { lo, hi }, 0);
                    Helpers.WriteToLog(cfg, "byteValue == 0x82, count= " + count.ToString());
                }
                else
                {
                    Helpers.WriteToLog(cfg, "we already have the data size");
                    count = byteValue;        // we already have the data size
                    Helpers.WriteToLog(cfg, "count= " + count.ToString());
                }

                Helpers.WriteToLog(cfg, "remove high order zeros in data");
                //remove high order zeros in data
                while (rd.ReadByte() == 0x00)
                {
                    count -= 1;
                }
                Helpers.WriteToLog(cfg, "count= " + count.ToString());
                rd.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);
                Helpers.WriteToLog(cfg, "End of DecodeIntegerSize");
            }
            catch (Exception ex)
            {
                Helpers.WriteToLog(cfg, "Exception in DecodeIntegerSize: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            Helpers.WriteToLog(cfg, "Exiting DecodeIntegerSize");
            return count;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pemString"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public static byte[] GetBytesFromPEM(RuntimeConfigurations cfg, string pemString, PemStringType type)
        {
            string header; string footer;
            byte[] bytes;
            try
            {
                WriteToLog(cfg, "Inside GetBytesFromPEM: " + type.ToString());
                switch (type)
                {
                    case PemStringType.Certificate:
                        header = "-----BEGIN CERTIFICATE-----";
                        footer = "-----END CERTIFICATE-----";
                        break;
                    case PemStringType.RsaPrivateKey:
                        header = "-----BEGIN RSA PRIVATE KEY-----";
                        footer = "-----END RSA PRIVATE KEY-----";
                        break;
                    default:
                        return null;
                }

                int start = pemString.IndexOf(header) + header.Length;
                WriteToLog(cfg, "Start: " + start.ToString());

                int end = pemString.IndexOf(footer, start) - start;
                WriteToLog(cfg, "End: " + end.ToString());

                WriteToLog(cfg, "Extracted value: " + pemString.Substring(start, end));

                bytes = Convert.FromBase64String(pemString.Substring(start, end));
                WriteToLog(cfg, "End of GetBytesFromPEM: " + type.ToString());
            }
            catch (Exception ex)
            {
                WriteToLog(cfg, "Exception in GetBytesFromPEM: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce: true);
                throw ex;
            }
            //return Convert.FromBase64String(pemString.Substring(start, end));
            WriteToLog(cfg, "Exiting GetBytesFromPEM: " + type.ToString());
            return bytes;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <param name="alignSize"></param>
        /// <returns></returns>
        public static byte[] AlignBytes(RuntimeConfigurations cfg, byte[] inputBytes, int alignSize)
        {
            WriteToLog(cfg, "Inside AlignBytes: ");
            int inputBytesSize;
            inputBytesSize = inputBytes.Length;

            WriteToLog(cfg, "inputBytesSize= " + inputBytesSize.ToString() + ", alignSize= " + alignSize.ToString());

            if ((alignSize != -1) && (inputBytesSize < alignSize))
            {
                byte[] buf = new byte[alignSize];
                for (int i = 0; i < inputBytesSize; ++i)
                {
                    buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
                }
                WriteToLog(cfg, "Exiting AlignBytes with buf");
                return buf;
            }
            else
            {
                WriteToLog(cfg, "Exiting AlignBytes with inputBytes : Already aligned, or doesn't need alignment");

                return inputBytes;      // Already aligned, or doesn't need alignment
            }
        }

        public static void WriteToLog(RuntimeConfigurations cfg, string msg, bool enforce = false)
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

    }
}
