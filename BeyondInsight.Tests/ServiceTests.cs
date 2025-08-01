using NUnit.Framework;
using BeyondInsight;
using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace BeyondInsight.Tests
{
    [TestFixture]
    public class ServiceTests
    {
        private HttpListener? _listener;

        [SetUp]
        public void Setup()
        {
            var rsa = RSA.Create();
            var req = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
            var base64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            Environment.SetEnvironmentVariable("BT_CLIENT_CERTIFICATE", $"-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----");
            Environment.SetEnvironmentVariable("BT_API_KEY", "dummy");
        }

        [TearDown]
        public void TearDown()
        {
            _listener?.Stop();
            _listener = null;
        }

        private static int GetFreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private void StartServer(string path, string method, string response, HttpStatusCode status = HttpStatusCode.OK, string? cookie = null)
        {
            int port = GetFreeTcpPort();
            string prefix = $"http://localhost:{port}/";
            _listener = new HttpListener();
            _listener.Prefixes.Add(prefix);
            _listener.Start();
            Environment.SetEnvironmentVariable("BT_API_URL", prefix.TrimEnd('/'));

            _ = Task.Run(async () =>
            {
                var ctx = await _listener.GetContextAsync();
                Assert.AreEqual(method, ctx.Request.HttpMethod);
                Assert.AreEqual(path, ctx.Request.Url!.AbsolutePath);
                if (cookie != null)
                    ctx.Response.AddHeader("Set-Cookie", cookie);
                byte[] buffer = Encoding.UTF8.GetBytes(response);
                ctx.Response.StatusCode = (int)status;
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });
        }

        private static void SetCookie(string value)
        {
            typeof(Service).GetField("cookie", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, value);
        }

        private static string GetCookie()
        {
            return (string)typeof(Service).GetField("cookie", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        }

        [Test]
        public async Task SignAppIn_ReturnsBodyAndSetsCookie()
        {
            StartServer("/Auth/SignAppin", "POST", "ok", HttpStatusCode.OK, "session=abc");
            var result = await Service.SignAppIn();
            Assert.AreEqual("ok", result);
            Assert.AreEqual("session=abc", GetCookie());
        }

        [Test]
        public async Task SignAppOut_ClearsCookie()
        {
            SetCookie("session=abc");
            StartServer("/Auth/Signout", "POST", string.Empty, HttpStatusCode.OK);
            var result = await Service.signAppOut();
            Assert.IsTrue(result);
            Assert.AreEqual(string.Empty, GetCookie());
        }

        [Test]
        public async Task GetCredentialByRequestID_ReturnsValue()
        {
            StartServer("/Credentials/1", "GET", "\"secret\"", HttpStatusCode.OK);
            var result = await Service.getCredentialByRequestID("1");
            Assert.AreEqual("secret", result);
        }
    }
}
