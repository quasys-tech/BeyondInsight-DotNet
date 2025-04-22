using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace BeyondInsight
{
    internal class Service
    {
        private static String cookie;
        
        /*private static void createHttpClient()
        {

        }*/
        public static async Task<string> SignAppIn()
        {
            String url = Settings.BT_API_URL + "/Auth/SignAppin";
            cookie = "";
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            //request.Headers.Authorization = new AuthenticationHeaderValue(Settings.REQUEST_HEADERS);
            request.Content = new StringContent("", System.Text.Encoding.UTF8, "application/json");


            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                if (response.Headers.TryGetValues("Set-Cookie", out var cookieValues))
                {
                    cookie = new List<string>(cookieValues)[0];
                }
                Utils.log("Logged Successfully", Microsoft.Extensions.Logging.LogLevel.Information);
                return responseBody.ToString();
            }
            Utils.log("Error trying to sign app in: " + responseBody.ToString(), Microsoft.Extensions.Logging.LogLevel.Error);
            return null;
        }

        public static async Task<bool> signAppOut()
        {
            String url = Settings.BT_API_URL + "/Auth/Signout";
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new StringContent("", System.Text.Encoding.UTF8, "application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                Utils.log("Logged Successfully", Microsoft.Extensions.Logging.LogLevel.Information);
                return true;
            }
            Utils.log("signAppOut: Error trying to sign app out: ", Microsoft.Extensions.Logging.LogLevel.Error);
            return false;
        }

        public static async Task<String> getSecretByPath(String path, String title, char separator, bool sendTitle)
        {
            String url = Settings.BT_API_URL + "/secrets-safe/secrets" + "?path=" + path + "&separator=" + separator;
            if (sendTitle)
            {
                url = Settings.BT_API_URL + "/secrets-safe/secrets" + "?title=" + title + "&path=" + path + "&separator=" + separator;
            }
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            request.Headers.Add("Cookie", cookie);
            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                return responseBody.ToString();
            }
            Utils.log("get_secret_by_path: Error trying to get secret by path:" + path + " and title " + title + ", response: " + responseBody.ToString(), Microsoft.Extensions.Logging.LogLevel.Error);
            if (!signAppOut().Result)
            {
                Utils.log("Eror trying to sign out!", Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }

        public static async Task<String> getSecretFilebyId(String secretId)
        {
            String url = Settings.BT_API_URL + "/secrets-safe/secrets/" + secretId + "/file/download";
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            request.Headers.Add("Cookie", cookie);
            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                return responseBody.ToString();
            }
            Utils.log(string.Format("get_file_by_id: Error trying to get file by secret Id {0}: {1}", secretId, response.ToString()), Microsoft.Extensions.Logging.LogLevel.Error);
            if (!signAppOut().Result)
            {
                Utils.log("Eror trying to sign out!", Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }

        public static async Task<String> getManagedAccounts(String systemName, String accountName)
        {
            String url = Settings.BT_API_URL + "/ManagedAccounts?systemName=" + systemName + "&accountName=" + accountName;
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            request.Headers.Add("Cookie", cookie);
            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                return responseBody.ToString();
            }
            Utils.log(string.Format("getManagedAccounts: Error trying to get secret by system name: {0} and account name {1}, response: {2}", systemName, accountName, responseBody.ToString()), Microsoft.Extensions.Logging.LogLevel.Error);
            if (!signAppOut().Result)
            {
                Utils.log("Eror trying to sign out!", Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }

        public static async Task<String> createRequestInPasswordSafe(int systemID, int accountID)
        {
            String url = Settings.BT_API_URL + "/Requests";
            string body = $@"
{{
    ""SystemID"": {systemID},
    ""AccountID"": {accountID},
    ""DurationMinutes"": 5,
    ""Reason"": ""Test"",
    ""ConflictOption"": ""reuse""
}}";
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            request.Headers.Add("Cookie", cookie);
            //request.Headers.Authorization = new AuthenticationHeaderValue(Settings.REQUEST_HEADERS);
            request.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");


            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
            {
                return responseBody.ToString();
            }
            Utils.log(string.Format("create_request: Error trying to create request, payload: {0}, response: {1}", body, responseBody.ToString()), Microsoft.Extensions.Logging.LogLevel.Error);
            if (!signAppOut().Result)
            {
                Utils.log("Eror trying to sign out!", Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }

        public static async Task<String> getCredentialByRequestID(String requestID)
        {
            String url = Settings.BT_API_URL + "/Credentials/" + requestID;
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls;
            HttpClient client = new HttpClient(handler);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", Settings.REQUEST_HEADERS);
            request.Headers.Add("Cookie", cookie);
            HttpResponseMessage response = await client.SendAsync(request);
            String responseBody = await response.Content.ReadAsStringAsync();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                //return responseBody.ToString();
                return Regex.Replace(responseBody, "^\"|\"$", "");
            }
            Utils.log(string.Format("get_credential_by_request_id: Error trying to get credential by request id: {0}, response: {1}", requestID, responseBody.ToString()), Microsoft.Extensions.Logging.LogLevel.Error);
            if (!signAppOut().Result)
            {
                Utils.log("Eror trying to sign out!", Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }
    }
}
