using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SecureText.Models;
using SecureText.Services;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Security.Cryptography;
using System.Text;

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
            if (HttpContext.Session.GetString("UserName") == null)
            {
                return RedirectToAction("SignUp");
            }
            return View();
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
            user.Password = Encrypt(user.Password);
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
            string hashPasword = Encrypt(user.Password);
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
        private string Encrypt(string inputText)
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

        // Mã hóa AES
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
                    return Convert.ToBase64String(ms.ToArray());  // Trả về Base64
                }
            }
        }
        public static string DecryptAES(string cipherTextBase64, byte[] key, byte[] iv)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextBase64);  // Chuyển Base64 về byte[]

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
