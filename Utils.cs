using Newtonsoft.Json.Linq;
using Serilog;
using System;
using System.IO;

namespace BeyondInsight
{
    internal class Utils
    {

        static Utils()
        {
            Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Trace()
            .CreateLogger();
        }

        public static void log(String message, LogLevel level)
        {
            switch (level)
            {
                case LogLevel.Trace:
                case LogLevel.Debug:
                    Log.Debug(message);
                    break;
                case LogLevel.Information:
                    Log.Information(message);
                    break;
                case LogLevel.Warning:
                    Log.Warning(message);
                    break;
                case LogLevel.Error:
                    Log.Error(message);
                    break;
                case LogLevel.Critical:
                    Log.Fatal(message);
                    break;
                default:
                    Log.Information(message);
                    break;
            }
        }

        public static JObject createSecretFile(JObject secret, String content)
        {
            String path = secret.Value<string>("FolderPath").Replace("\\", "/") + "/" + secret.Value<string>("Title");
            String filePath = createFolders(path);
            File.WriteAllText(filePath, content + "\n");

            JObject jsonObject = new JObject();
            jsonObject.Add("Password", secret.Value<string>("Password") ?? "");
            jsonObject.Add("Title", secret.Value<string>("Title"));
            jsonObject.Add("Username", secret.Value<string>("Username") ?? "");
            jsonObject.Add("FolderPath", secret.Value<string>("FolderPath"));
            jsonObject.Add("FilePath", filePath);
            jsonObject.Add("IsFileSecret", true);
            return jsonObject;
        }

        public static JObject convertSecretToObject(JObject secret)
        {
            JObject jsonObject = new JObject();
            jsonObject.Add("Password", secret.Value<string>("Password"));
            jsonObject.Add("Title", secret.Value<string>("Title"));
            jsonObject.Add("Username", secret.Value<string>("Username") ?? "");
            jsonObject.Add("FolderPath", secret.Value<string>("FolderPath"));
            jsonObject.Add("FilePath", "");
            jsonObject.Add("IsFileSecret", false);
            return jsonObject;
        }
        

        public static JObject convertManagedAccountToObject(JObject secret, String content)
        {
            JObject jsonObject = new JObject();
            jsonObject.Add("Password", content);
            jsonObject.Add("SystemName", secret.Value<string>("SystemName"));
            jsonObject.Add("AccountName", secret.Value<string>("AccountName"));
            jsonObject.Add("FolderPath", secret.Value<string>("SystemName") + "/" + secret.Value<string>("AccountName"));
            jsonObject.Add("IsFileSecret", false);
            return jsonObject;
        }

        public static String createFolders(String path)
        {
            string folderPath = Path.Combine(Settings.SECRETS_PATH, path);
            string parentDirectory = Path.GetDirectoryName(folderPath);

            if (!Directory.Exists(parentDirectory))
            {
                Directory.CreateDirectory(parentDirectory);
            }
            return folderPath;
        }
    }
}
