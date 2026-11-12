using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using StandaloneLapsWeb;

namespace StandaloneLaps.FrameworkAgent
{
    public sealed class ApiBackupClient : IBackupClient
    {
        private readonly AgentPolicy policy; private readonly X509Certificate2 certificate;
        public ApiBackupClient(AgentPolicy policy, X509Certificate2 certificate) { this.policy = policy; this.certificate = certificate; }
        public void StoreAndVerify(Envelope envelope, CancellationToken token)
        {
            var path = "api.aspx?device=" + policy.DeviceId + "&rotation=" + envelope.rotationId.ToString("D");
            Request("PUT", path, EnvelopeJson.Serialize(envelope), token);
            var stored = EnvelopeJson.Deserialize<Envelope>(Request("GET", path, null, token));
            if (stored == null || EnvelopeJson.Serialize(stored) != EnvelopeJson.Serialize(envelope)) throw new InvalidDataException("Backup read-back mismatch.");
        }
        public void ReportApplied(Guid rotationId, CancellationToken token)
        { Request("POST", "api.aspx?device=" + policy.DeviceId + "&rotation=" + rotationId.ToString("D") + "&action=applied", null, token); }
        private string Request(string method, string path, string body, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var request = (HttpWebRequest)WebRequest.Create(new Uri(policy.ApiUrl, path));
            request.Method = method; request.AllowAutoRedirect = false; request.Timeout = 30000; request.ReadWriteTimeout = 30000;
            request.ClientCertificates.Add(certificate); request.ContentType = "application/json"; request.Accept = "application/json";
            using (token.Register(request.Abort))
            {
                if (body != null)
                {
                    var bytes = Encoding.UTF8.GetBytes(body); request.ContentLength = bytes.Length;
                    using (var output = request.GetRequestStream()) output.Write(bytes, 0, bytes.Length);
                }
                else if (method == "POST") request.ContentLength = 0;
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    if ((int)response.StatusCode < 200 || (int)response.StatusCode >= 300) throw new WebException("API returned a non-success status.");
                    if (response.ContentLength > 65536) throw new InvalidDataException("API response is too large.");
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        var buffer = new char[65537]; var used = 0; int read;
                        while (used < buffer.Length && (read = reader.Read(buffer, used, buffer.Length - used)) > 0) used += read;
                        if (used > 65536) throw new InvalidDataException("API response is too large.");
                        return new string(buffer, 0, used);
                    }
                }
            }
        }
    }
}
