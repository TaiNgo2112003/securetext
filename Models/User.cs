using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace SecureText.Models
{
    public class User
    {
        [BsonId] 
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        [BsonElement("Email")]
        public string Username { get; set; }

        [BsonElement("PasswordHash")]
        public string Password { get; set; }
    }
}
