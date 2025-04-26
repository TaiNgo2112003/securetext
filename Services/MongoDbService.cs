using MongoDB.Driver;

namespace SecureText.Services
{
    public class MongoDbService
    {
        private readonly IMongoDatabase _database;

        public MongoDbService()
        {
            var connectionString = "mongodb+srv://taingo2112003:sKDQQdN3BnhXzcE7@securetext.7lxbomu.mongodb.net/?retryWrites=true&w=majority&appName=SecureText";
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase("SecureTextDb"); // tên database bạn muốn (chưa có sẽ tự tạo)
        }

        public IMongoDatabase GetDatabase()
        {
            return _database;
        }
    }
}
