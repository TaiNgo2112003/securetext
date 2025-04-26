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
            return View();
        }

        [HttpPost]
        public IActionResult Encrypt(string inputText)
        {
            if (string.IsNullOrEmpty(inputText))
            {
                ViewBag.Result = "Bạn chưa nhập nội dung!";
                return View("Index");
            }

            // Dùng SHA-256 để băm
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(inputText);
                var hashBytes = sha256.ComputeHash(bytes);
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                // Lưu kết quả vào MongoDB
                var database = _mongoDbService.GetDatabase();
                var collection = database.GetCollection<BsonDocument>("EncryptResults");

                var document = new BsonDocument
                {
                    { "Input", inputText },
                    { "Result", hashString },
                    { "CreatedAt", DateTime.UtcNow }
                };

                collection.InsertOne(document);

                ViewBag.Result = hashString;
            }

            return View("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
