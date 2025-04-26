using MongoDB.Driver;
using Microsoft.Extensions.Configuration;

namespace SecureText.Services
{
    public class MongoDbService
    {
        private readonly IMongoDatabase _database;

        public MongoDbService(IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("MongoDb");
            var databaseName = configuration["MongoDbSettings:DatabaseName"];
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase(databaseName);
        }

        public IMongoDatabase GetDatabase()
        {
            return _database;
        }
    }
}
