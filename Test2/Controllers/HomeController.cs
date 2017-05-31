using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace Test2.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public JsonResult getDataPass(string text)
        {
            var keyAESCrypt = GenereteAESKey();

            var Encrypt256Result = Encrypt256(keyAESCrypt, text);

            var EncDecrKeyAESBytes = RSAEncDecr(keyAESCrypt.Key);
            /////////////// Create new AES
            var NewKeyAfterCrypt = new AesCryptoServiceProvider();
            NewKeyAfterCrypt.KeySize = 256;
            NewKeyAfterCrypt.Key = EncDecrKeyAESBytes;
            NewKeyAfterCrypt.IV = keyAESCrypt.IV;
            //////////////////////  IV - can send as Open

            var decryptAES = Decrypt256(NewKeyAfterCrypt, Encrypt256Result);

            return Json(new { EncryptText = "1" });// encryptData, DecryptText  = decryptData });
        }
        
        public AesCryptoServiceProvider GenereteAESKey()
        {
            AesCryptoServiceProvider keyCrypt = new AesCryptoServiceProvider();
            keyCrypt.KeySize = 256;
            keyCrypt.GenerateKey();
            return keyCrypt;
        }
        private string Encrypt256(AesCryptoServiceProvider keyAESCrypt, string text)
        {
            keyAESCrypt.KeySize = 256;
            keyAESCrypt.GenerateKey();
            byte[] src = Encoding.Unicode.GetBytes(text);
            using (ICryptoTransform encrypt = keyAESCrypt.CreateEncryptor())
            {
                byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                return Convert.ToBase64String(dest);
            }
        }

        private string Decrypt256(AesCryptoServiceProvider keyCrypt, string text )
        {
            byte[] src = System.Convert.FromBase64String(text);
            using (ICryptoTransform decrypt = keyCrypt.CreateDecryptor())
            {
                byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                return Encoding.Unicode.GetString(dest);
            }
        }


        public static void GenerateRSAKeyPair(out string publicKey, out string privateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            publicKey = rsa.ToXmlString(false);
            privateKey = rsa.ToXmlString(true);
        }



        public byte[] RSAEncDecr(byte[] keyAESCryptKey)
        {

            var csp = new RSACryptoServiceProvider(2048);
            var privKey = csp.ExportParameters(true);
            var pubKey = csp.ExportParameters(false);

            //string pubKeyString;
            //{
            //    var sw = new System.IO.StringWriter();
            //    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //    xs.Serialize(sw, pubKey);
            //    pubKeyString = sw.ToString();
            //}
            //{
            //    var sr = new System.IO.StringReader(pubKeyString);
            //    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //    pubKey = (RSAParameters)xs.Deserialize(sr);
            //}
            ////////////////////////////////////////////////////////////////////////////////////////////////////////////
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);
            var bytesCypherText = csp.Encrypt(keyAESCryptKey, false);
            var cypherText = Convert.ToBase64String(bytesCypherText);
            bytesCypherText = Convert.FromBase64String(cypherText);
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////

            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privKey);
            keyAESCryptKey = csp.Decrypt(bytesCypherText, false);
            return keyAESCryptKey;
        }

    }
}