using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace OnamaPaymentGateway
{
    public class Crypto
    {
        /// <summary>
        /// This helper function parses an RSA private key using the ASN.1 format
        /// </summary>
        /// <param name="privateKeyBytes">Byte array containing PEM string of private key.</param>
        /// <returns>An instance of <see cref="RSACryptoServiceProvider"/> rapresenting the requested private key.
        /// Null if method fails on retriving the key.</returns>
        public static RSACryptoServiceProvider DecodeRsaPrivateKey(RuntimeConfigurations cfg, byte[] privateKeyBytes)
        {
            Helpers.WriteToLog(cfg, "Inside DecodeRsaPrivateKey");

            MemoryStream ms = new MemoryStream(privateKeyBytes);
            BinaryReader rd = new BinaryReader(ms);

            try
            {

                byte byteValue;
                ushort shortValue;

                Helpers.WriteToLog(cfg, "Before rd.ReadUInt16()");
                shortValue = rd.ReadUInt16();
                Helpers.WriteToLog(cfg, "shortValue: " + shortValue.ToString());

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        Helpers.WriteToLog(cfg, "Case shortValue: 0x8130");
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        Helpers.WriteToLog(cfg, "Case shortValue: 0x8230");
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:
                        Helpers.WriteToLog(cfg, "Case shortValue: Improper ASN.1 format. Returning NULL");
                        //Debug.Assert(false);     // Improper ASN.1 format
                        return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue != 0x0102) // (version number)
                {
                    Helpers.WriteToLog(cfg, "shortValue != 0x0102: Improper ASN.1 format, unexpected version number. Returning NULL");
                    //Debug.Assert(false);     // Improper ASN.1 format, unexpected version number
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {
                    Helpers.WriteToLog(cfg, "byteValue != 0x00: Improper ASN.1 format. Returning NULL");
                    //Debug.Assert(false);     // Improper ASN.1 format
                    return null;
                }

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();

                //parms.Flags = CspProviderFlags.NoFlags;
                parms.Flags = CspProviderFlags.UseMachineKeyStore;

                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();

                Helpers.WriteToLog(cfg, "Creating CspParameters parms.KeyContainerName: " + parms.KeyContainerName);

                Helpers.WriteToLog(cfg, "Setting parms.ProviderType");
                Helpers.WriteToLog(cfg, "Environment.OSVersion.Version.Major: " + Environment.OSVersion.Version.Major.ToString());
                Helpers.WriteToLog(cfg, "Environment.OSVersion.Version.Minor: " + Environment.OSVersion.Version.Minor.ToString());

                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;
                Helpers.WriteToLog(cfg, "Setting parms.ProviderType: " + parms.ProviderType.ToString());


                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                Helpers.WriteToLog(cfg, "After creating RSACryptoServiceProvider(parms)");

                RSAParameters rsAparams = new RSAParameters();
                Helpers.WriteToLog(cfg, "After creating RSAParameters rsAparams");

                rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = Helpers.AlignBytes(cfg, rsAparams.Modulus, traits.size_Mod);
                rsAparams.Exponent = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_Exp);
                rsAparams.D = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_D);
                rsAparams.P = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_P);
                rsAparams.Q = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_Q);
                rsAparams.DP = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_DP);
                rsAparams.DQ = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_DQ);
                rsAparams.InverseQ = Helpers.AlignBytes(cfg, rd.ReadBytes(Helpers.DecodeIntegerSize(cfg, rd)), traits.size_InvQ);

                Helpers.WriteToLog(cfg, "Before importing rsAparams in rsa");
                rsa.ImportParameters(rsAparams);
                Helpers.WriteToLog(cfg, "Exiting DecodeRsaPrivateKey");
                return rsa;
            }
            catch (Exception ex)
            {
                Helpers.WriteToLog(cfg, "Exception in DecodeRsaPrivateKey: " + ex.Message + Environment.NewLine + ex.StackTrace, enforce:true);
                throw ex;
                //Debug.Assert(false);
                //return null;
            }
            finally
            {
                rd.Close();
            }
        }
    }
}
