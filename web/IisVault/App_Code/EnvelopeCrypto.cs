using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StandaloneLapsWeb
{
    // .NET Framework has no AesGcm class. Use Windows' BCrypt AES-GCM implementation,
    // preserving the exact v1 wire format of the .NET agent without a third-party DLL.
    public static class EnvelopeCrypto
    {
        public static string Fingerprint(X509Certificate2 certificate)
        { using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(certificate.RawData)).Replace("-", ""); }
        private static DateTimeOffset Timestamp(string value) { return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.None); }
        private static byte[] AssociatedData(Envelope envelope)
        { return Encoding.UTF8.GetBytes(string.Format(CultureInfo.InvariantCulture, "StandaloneLaps/v1|{0}|{1:D}|{2:O}|{3}|{4}", envelope.deviceId, envelope.rotationId, Timestamp(envelope.createdUtc), envelope.recipientSha256, envelope.wrappedKey)); }

        public static Envelope Encrypt(Payload payload, X509Certificate2 certificate)
        {
            var key = new byte[32]; var nonce = new byte[12]; var tag = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(key); rng.GetBytes(nonce); }
            var plaintext = Encoding.UTF8.GetBytes(EnvelopeJson.Serialize(payload));
            try
            {
                using (var rsa = certificate.GetRSAPublicKey())
                {
                    if (rsa == null || rsa.KeySize < 3072) throw new CryptographicException("RSA 3072 or stronger required.");
                    var envelope = new Envelope { version = 1, deviceId = payload.deviceId, rotationId = payload.rotationId, createdUtc = payload.createdUtc,
                        recipientSha256 = Fingerprint(certificate), wrappedKey = Convert.ToBase64String(rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256)), nonce = Convert.ToBase64String(nonce) };
                    envelope.ciphertext = Convert.ToBase64String(GcmTransform(key, nonce, plaintext, tag, AssociatedData(envelope), true));
                    envelope.tag = Convert.ToBase64String(tag);
                    return envelope;
                }
            }
            finally { Array.Clear(key, 0, key.Length); Array.Clear(plaintext, 0, plaintext.Length); }
        }

        public static Payload Decrypt(Envelope envelope, X509Certificate2 certificate)
        {
            if (envelope == null || envelope.version != 1 || Fingerprint(certificate) != envelope.recipientSha256)
                throw new CryptographicException("Unsupported envelope or incorrect recovery certificate.");
            byte[] key;
            using (var rsa = certificate.GetRSAPrivateKey())
            {
                if (rsa == null) throw new CryptographicException("RSA private key required.");
                key = rsa.Decrypt(Convert.FromBase64String(envelope.wrappedKey), RSAEncryptionPadding.OaepSHA256);
            }
            byte[] plaintext = null;
            try
            {
                plaintext = GcmTransform(key, Convert.FromBase64String(envelope.nonce), Convert.FromBase64String(envelope.ciphertext), Convert.FromBase64String(envelope.tag), AssociatedData(envelope), false);
                var payload = EnvelopeJson.Deserialize<Payload>(Encoding.UTF8.GetString(plaintext));
                if (payload == null || payload.version != 1 || payload.deviceId != envelope.deviceId || payload.rotationId != envelope.rotationId ||
                    Timestamp(payload.createdUtc) != Timestamp(envelope.createdUtc)) throw new CryptographicException("Payload metadata mismatch.");
                return payload;
            }
            finally { Array.Clear(key, 0, key.Length); if (plaintext != null) Array.Clear(plaintext, 0, plaintext.Length); }
        }

        private static byte[] GcmTransform(byte[] secret, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad, bool encrypt)
        {
            if (secret.Length != 32 || nonce.Length != 12 || tag.Length != 16) throw new CryptographicException("Invalid AES-GCM parameters.");
            IntPtr algorithm = IntPtr.Zero, key = IntPtr.Zero, noncePointer = IntPtr.Zero, tagPointer = IntPtr.Zero, aadPointer = IntPtr.Zero;
            var plaintext = new byte[ciphertext.Length];
            try
            {
                Check(BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0));
                var mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                Check(BCryptSetProperty(algorithm, "ChainingMode", mode, mode.Length, 0));
                Check(BCryptGenerateSymmetricKey(algorithm, out key, IntPtr.Zero, 0, secret, secret.Length, 0));
                noncePointer = Copy(nonce); tagPointer = Copy(tag); aadPointer = Copy(aad);
                var info = new AuthInfo { Size = Marshal.SizeOf(typeof(AuthInfo)), Version = 1,
                    Nonce = noncePointer, NonceLength = nonce.Length, AuthData = aadPointer, AuthDataLength = aad.Length, Tag = tagPointer, TagLength = tag.Length };
                int written;
                Check(encrypt ? BCryptEncrypt(key, ciphertext, ciphertext.Length, ref info, null, 0, plaintext, plaintext.Length, out written, 0)
                    : BCryptDecrypt(key, ciphertext, ciphertext.Length, ref info, null, 0, plaintext, plaintext.Length, out written, 0));
                if (encrypt) Marshal.Copy(tagPointer, tag, 0, tag.Length);
                if (written != plaintext.Length) throw new CryptographicException("Unexpected decrypted length.");
                return plaintext;
            }
            catch { Array.Clear(plaintext, 0, plaintext.Length); throw; }
            finally
            {
                if (key != IntPtr.Zero) BCryptDestroyKey(key);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
                if (noncePointer != IntPtr.Zero) Marshal.FreeHGlobal(noncePointer);
                if (tagPointer != IntPtr.Zero) Marshal.FreeHGlobal(tagPointer);
                if (aadPointer != IntPtr.Zero) Marshal.FreeHGlobal(aadPointer);
            }
        }
        private static IntPtr Copy(byte[] bytes) { var pointer = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, pointer, bytes.Length); return pointer; }
        private static void Check(int status) { if (status != 0) throw new CryptographicException("Windows cryptography operation failed."); }
        [StructLayout(LayoutKind.Sequential)]
        private struct AuthInfo
        {
            public int Size, Version;
            public IntPtr Nonce; public int NonceLength;
            public IntPtr AuthData; public int AuthDataLength;
            public IntPtr Tag; public int TagLength;
            public IntPtr MacContext; public int MacContextLength;
            public int AadLength; public ulong DataLength; public int Flags;
        }
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algorithm, string implementation, int flags);
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptSetProperty(IntPtr handle, string name, byte[] value, int size, int flags);
        [DllImport("bcrypt.dll")] private static extern int BCryptGenerateSymmetricKey(IntPtr algorithm, out IntPtr key, IntPtr keyObject, int keyObjectLength, byte[] secret, int secretLength, int flags);
        [DllImport("bcrypt.dll")] private static extern int BCryptDecrypt(IntPtr key, byte[] input, int inputLength, ref AuthInfo info, byte[] iv, int ivLength, byte[] output, int outputLength, out int written, int flags);
        [DllImport("bcrypt.dll")] private static extern int BCryptEncrypt(IntPtr key, byte[] input, int inputLength, ref AuthInfo info, byte[] iv, int ivLength, byte[] output, int outputLength, out int written, int flags);
        [DllImport("bcrypt.dll")] private static extern int BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt.dll")] private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, int flags);
    }
}
