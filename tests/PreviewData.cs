using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StandaloneLapsWeb;

public sealed class PreviewSeedRunner : MarshalByRefObject
{
    public int Run(string directory)
    {
        Directory.CreateDirectory(Vault.DataRoot);
        var devices = new[] { "2b0c7224-6121-4181-9dbc-65be629c6069", "8e8c6483-b1cb-461c-90be-6a833ded6b23", "f69d77c2-cea6-4203-98c8-478a225ba1a9" };
        var names = new[] { "DMZ-WEB-01", "DMZ-APP-02", "DMZ-SFTP-01" };
        var clients = new Client[devices.Length];
        using (var rsa = new RSACng(3072))
        {
            var request = new CertificateRequest("CN=Preview-Only-Ephemeral-Recovery", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using (var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
            {
                for (var deviceIndex = 0; deviceIndex < devices.Length; deviceIndex++)
                {
                    clients[deviceIndex] = new Client { role = "agent", deviceId = devices[deviceIndex], displayName = names[deviceIndex], certificateSha256 = new string((char)('A' + deviceIndex), 64) };
                    for (var generation = 3; generation >= 0; generation--)
                    {
                        var id = Guid.NewGuid();
                        var envelope = EnvelopeCrypto.Encrypt(new Payload { version = 1, deviceId = devices[deviceIndex], rotationId = id,
                            createdUtc = DateTimeOffset.UtcNow.AddDays(-generation * 30).ToString("O"), computerName = names[deviceIndex], accountName = "Administrator",
                            accountSid = "S-1-5-21-111-222-333-500", password = "SYNTHETIC-PREVIEW-ONLY-123!" }, certificate);
                        Vault.Put(Guid.Parse(devices[deviceIndex]), id, envelope);
                        if (!(deviceIndex == 0 && generation == 0)) Vault.Applied(Guid.Parse(devices[deviceIndex]), id);
                    }
                }
            }
        }
        File.WriteAllText(Path.Combine(directory, "site", "App_Data", "clients.json"), Vault.Json.Serialize(clients));
        // The preview recovery key was ephemeral and is discarded. This UI demo cannot decrypt any real credential.
        return 0;
    }
}
