using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
namespace StandaloneLapsWeb
{
    // Shared with the agent. Uses the base framework serializer so DMZ servers need no ASP.NET assemblies.
    public static class EnvelopeJson
    {
        public static string Serialize<T>(T value)
        {
            using (var stream = new MemoryStream())
            {
                try { new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value); return Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length); }
                finally { Array.Clear(stream.GetBuffer(), 0, (int)stream.Length); }
            }
        }
        public static T Deserialize<T>(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            try { using (var stream = new MemoryStream(bytes)) return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
    }
    public sealed class Envelope
    {
        public int version { get; set; }
        public string deviceId { get; set; }
        public Guid rotationId { get; set; }
        public string createdUtc { get; set; }
        public string recipientSha256 { get; set; }
        public string wrappedKey { get; set; }
        public string nonce { get; set; }
        public string tag { get; set; }
        public string ciphertext { get; set; }
    }
    public sealed class Payload
    {
        public int version { get; set; }
        public string deviceId { get; set; }
        public Guid rotationId { get; set; }
        public string createdUtc { get; set; }
        public string computerName { get; set; }
        public string accountName { get; set; }
        public string accountSid { get; set; }
        public string password { get; set; }
    }
}
