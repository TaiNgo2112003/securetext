using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SecureText.Models;
using SecureText.Services;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace SecureText.Controllers
{

    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly MongoDbService _mongoDbService;
        public HomeController(ILogger<HomeController> logger, MongoDbService mongoDbService)
        {
            _logger = logger;
            _mongoDbService = mongoDbService;
        }
        [HttpGet]
        public IActionResult Index()
        {
            // if (HttpContext.Session.GetString("UserName") == null)
            // {
            //     return RedirectToAction("SignUp");
            // }
            ViewBag.AesKey = GenerateRandomString(16);
            ViewBag.AesIV = GenerateRandomString(16);
            ViewBag.DesKey = GenerateRandomString(8);
            ViewBag.DesIV = GenerateRandomString(8);
            ViewBag.TripleDesKey = GenerateRandomString(24);
            ViewBag.TripleDesIV = GenerateRandomString(8);


            return View();
        }
        public IActionResult Hash()
        {
            return View();
        }
        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                                        .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        [HttpGet]
        public ActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public IActionResult SignUp(User user)
        {
            var database = _mongoDbService.GetDatabase();
            var users = database.GetCollection<User>("Users");
            if (string.IsNullOrEmpty(user.Username) || string.IsNullOrEmpty(user.Password))
            {
                ViewBag.Result = "Bạn chưa nhập tên đăng nhập hoặc mật khẩu!";
                return View(user);
            }
            var existingUser = users.Find(u => u.Username == user.Username).FirstOrDefault();
            if (existingUser != null)
            {
                ViewBag.error = "Tên đăng nhập đã tồn tại!";
                return View("SignUp");
            }
            user.Password = Hash256(user.Password);
            users.InsertOne(user);
            HttpContext.Session.SetString("UserName", user.Username);
            return RedirectToAction("Index");
        }
        public IActionResult SignIn(User user)
        {
            var database = _mongoDbService.GetDatabase();
            var users = database.GetCollection<User>("Users");
            if (string.IsNullOrEmpty(user.Username) || string.IsNullOrEmpty(user.Password))
            {
                ViewBag.Result = "Bạn chưa nhập tên đăng nhập hoặc mật khẩu!";
                return View("SignUp");
            }
            string hashPasword = Hash256(user.Password);
            var existingUser = users.Find(u => u.Username == user.Username && u.Password == hashPasword).FirstOrDefault();
            if (existingUser == null)
            {
                ViewBag.error = "Tên đăng nhập hoặc mật khẩu không đúng!";
                return View("SignUp");
            }
            HttpContext.Session.SetString("UserName", user.Username);
            return RedirectToAction("Index");
        }

        /*================================Các thuật toán ở đây============================================*/
        //Cái này hàm băm, Tài dùng để băm mật khẩu trước khi lưu vào database
        [HttpPost]
        public IActionResult HashSHA256([FromBody] string inputText)
        {
            if (string.IsNullOrEmpty(inputText))
            {
                return BadRequest("Input text cannot be empty.");
            }

            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(inputText);
                var hashBytes = sha256.ComputeHash(bytes);
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                return Content(hashString); // hoặc Json(new { result = hashString }) nếu bạn muốn thống nhất format
            }
        }

        [HttpPost]
        private string Hash256(string inputText)
        {
            if (string.IsNullOrEmpty(inputText))
            {
                return "";
            }
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(inputText);
                var hashBytes = sha256.ComputeHash(bytes);
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                return hashString;
            }
        }
        [HttpPost]
        public IActionResult HashMD5([FromBody] string inputText)
        {
            if (string.IsNullOrEmpty(inputText))
            {
                return BadRequest("Input text for MD5 cannot be empty.");
            }

            using (var md5 = MD5.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(inputText);
                var hashBytes = md5.ComputeHash(bytes);
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                return Content(hashString); // đồng nhất với Hash256
            }
        }



        /*================================Mã hóa bất đối xứng============================================*/
        private const string PublicKeySessionKey = "RSAPublicKey";
        private const string PrivateKeySessionKey = "RSAPrivateKey";
        public IActionResult AsymmetricEncryption()
        {
            // Tạo khóa mới nếu chưa có trong Session
            if (HttpContext.Session.GetString(PublicKeySessionKey) == null)
            {
                var (publicKey, privateKey) = RSAHelper.GenerateKeys();

                // Lưu khóa XML vào Session
                HttpContext.Session.SetString(PublicKeySessionKey,
                    RSAHelper.ExportToXml(publicKey, false));
                HttpContext.Session.SetString(PrivateKeySessionKey,
                    RSAHelper.ExportToXml(privateKey, true));

                // Cái này in ra thôi không sử dụng
                var publicKeyPem = RSAHelper.ExportPublicKeyToPEM(publicKey);
                var privateKeyPem = RSAHelper.ExportPrivateKeyToPEM(privateKey);

                // Lưu PEM vào Session (hoặc bạn có thể dùng ViewBag để truyền cho View)
                HttpContext.Session.SetString("PublicKeyPEM", publicKeyPem);
                HttpContext.Session.SetString("PrivateKeyPEM", privateKeyPem);
            }

            ViewBag.RSAPublicKey = HttpContext.Session.GetString(PublicKeySessionKey);
            ViewBag.PublicKeyPEM = HttpContext.Session.GetString("PublicKeyPEM");
            ViewBag.PrivateKeyPEM = HttpContext.Session.GetString("PrivateKeyPEM");

            return View();
        }
        [HttpPost]
        public IActionResult GenerateNewKeys()
        {
            // Generate new keys
            var (publicKey, privateKey) = RSAHelper.GenerateKeys();

            // Convert to XML and PEM formats
            var publicKeyXml = RSAHelper.ExportToXml(publicKey, false);
            var privateKeyXml = RSAHelper.ExportToXml(privateKey, true);
            var publicKeyPem = RSAHelper.ExportPublicKeyToPEM(publicKey);
            var privateKeyPem = RSAHelper.ExportPrivateKeyToPEM(privateKey);

            // Store in session
            HttpContext.Session.SetString(PublicKeySessionKey, publicKeyXml);
            HttpContext.Session.SetString(PrivateKeySessionKey, privateKeyXml);
            HttpContext.Session.SetString("PublicKeyPEM", publicKeyPem);
            HttpContext.Session.SetString("PrivateKeyPEM", privateKeyPem);

            return Ok(new
            {
                publicKey = publicKeyXml,
                privateKey = privateKeyPem
            });
        }
        [HttpPost]
        public IActionResult ProcessRSA([FromBody] RSARequestModel request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Text))
                    return BadRequest(new { error = "Text cannot be empty." });

                string result;
                var privateKeyXml = HttpContext.Session.GetString(PrivateKeySessionKey);
                _logger.LogInformation("Private Key from Session: {PrivateKey}", privateKeyXml);

                switch (request.Action.ToLower())
                {
                    case "encrypt":
                        var publicKey = RSAHelper.ImportFromXml(request.PublicKeyXml, false);
                        result = RSAHelper.Encrypt(request.Text, publicKey);
                        break;

                    case "decrypt":
                        var privateKey = RSAHelper.ImportFromXml(privateKeyXml, true);
                        result = RSAHelper.Decrypt(request.Text, privateKey);
                        break;

                    default:
                        return BadRequest(new { error = "Invalid action specified." });
                }

                return Ok(new { result });
            }
            catch (Exception ex)
            {
                // Log error ở đây (sử dụng ILogger trong production)
                return StatusCode(500, new { error = "An error occurred during processing." });
            }
        }

        // Model cho request
        public class RSARequestModel
        {
            public string Action { get; set; }
            public string Text { get; set; }
            public string PublicKeyXml { get; set; }
        }

        /*================================Mã hóa đối xứng============================================*/

        // Mã hóa AES
        [HttpPost]
        public IActionResult ProcessAES(string action, string text, string key, string iv)
        {
            try
            {
                // Đổi cách lấy key và iv: dùng UTF8, không decode base64
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                string result = "";
                if (action == "encrypt")
                {
                    result = EncryptAES(text, keyBytes, ivBytes);
                }
                else
                {
                    result = DecryptAES(text, keyBytes, ivBytes);
                }

                return Json(new { success = true, result = result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        [HttpPost]
        public IActionResult ProcessDES(string action, string text, string key, string iv)
        {
            try
            {
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);


                string result = "";
                if (action == "encrypt")
                {
                    var encryptedBytes = EncryptDES(text, keyBytes, ivBytes);
                    result = Convert.ToBase64String(encryptedBytes);
                }
                else
                {
                    var cipherText = Convert.FromBase64String(text);
                    result = DecryptDES(cipherText, keyBytes, ivBytes);
                }

                return Json(new { success = true, result = result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        [HttpPost]
        public IActionResult ProcessTripleDES(string action, string text, string key, string iv)
        {
            try
            {
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                string result = "";
                if (action == "encrypt")
                {
                    var encryptedBytes = EncryptTripleDES(text, keyBytes, ivBytes);
                    result = Convert.ToBase64String(encryptedBytes);
                }
                else
                {
                    var cipherText = Convert.FromBase64String(text);
                    result = DecryptTripleDES(cipherText, keyBytes, ivBytes);
                }

                return Json(new { success = true, result = result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }


        public static string EncryptAES(string plainText, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                    sw.Flush();
                    cs.FlushFinalBlock();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public static string DecryptAES(string cipherTextBase64, byte[] key, byte[] iv)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipherText))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        public static byte[] EncryptDES(string plainText, byte[] key, byte[] iv)
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.IV = iv;

                ICryptoTransform encryptor = des.CreateEncryptor(des.Key, des.IV);

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                    sw.Flush();
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static string DecryptDES(byte[] cipherText, byte[] key, byte[] iv)
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.IV = iv;

                ICryptoTransform decryptor = des.CreateDecryptor(des.Key, des.IV);

                using (MemoryStream ms = new MemoryStream(cipherText))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        public static byte[] EncryptTripleDES(string plainText, byte[] key, byte[] iv)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = key;
                tdes.IV = iv;

                ICryptoTransform encryptor = tdes.CreateEncryptor(tdes.Key, tdes.IV);

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                    sw.Flush();
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static string DecryptTripleDES(byte[] cipherText, byte[] key, byte[] iv)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = key;
                tdes.IV = iv;

                ICryptoTransform decryptor = tdes.CreateDecryptor(tdes.Key, tdes.IV);

                using (MemoryStream ms = new MemoryStream(cipherText))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }


        public static byte[] EncryptRC4(string plainText, byte[] key)
        {
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }

            int a = 0;
            j = 0;
            byte[] output = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                a = (a + 1) % 256;
                j = (j + s[a]) % 256;
                (s[a], s[j]) = (s[j], s[a]);
                int k = s[(s[a] + s[j]) % 256];
                output[i] = (byte)(data[i] ^ k);
            }

            return output;
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
