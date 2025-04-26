using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using SecureText.Services;

namespace SecureText.Controllers
{
    public class TestMongoController : Controller
    {
        private readonly MongoDbService _mongoDbService;

        public TestMongoController(MongoDbService mongoDbService)
        {
            _mongoDbService = mongoDbService;
        }

        public IActionResult Index()
        {
            var database = _mongoDbService.GetDatabase();
            var collection = database.GetCollection<BsonDocument>("TestCollection");

            var document = new BsonDocument
            {
                { "Name", "Test" },
                { "CreatedAt", DateTime.UtcNow }
            };

            collection.InsertOne(document);

            return Content("Đã insert 1 document test vào MongoDB!");
        }
    }
}
