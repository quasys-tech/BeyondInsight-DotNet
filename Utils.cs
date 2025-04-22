using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json.Nodes;

namespace BeyondInsight
{
    internal class Utils
    {
        private static ILogger _logger;
        static Utils()
        {
            using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            _logger = loggerFactory.CreateLogger<Utils>();
        }

        public static void log(String message, LogLevel level)
        {
            switch (level)
            {
                case LogLevel.Trace:
                    _logger.LogTrace(message);
                    break;
                case LogLevel.Debug:
                    _logger.LogDebug(message);
                    break;
                case LogLevel.Information:
                    _logger.LogInformation(message);
                    break;
                case LogLevel.Warning:
                    _logger.LogWarning(message);
                    break;
                case LogLevel.Error:
                    _logger.LogError(message);
                    break;
                case LogLevel.Critical:
                    _logger.LogCritical(message);
                    break;
                default:
                    _logger.LogInformation(message);
                    break;
            }
        }

        public static JsonObject createSecretFile(JsonObject secret, String content)
        {
            String path = secret["FolderPath"].GetValue<string>().Replace("\\", "/") + "/" + secret["Title"].GetValue<string>();
            String filePath = createFolders(path);
            File.WriteAllText(filePath, content + "\n");

            JsonObject jsonObject = new JsonObject();
            jsonObject.Add("Password", secret["Password"]?.GetValue<string>() ?? "");
            jsonObject.Add("Title", secret["Title"]?.GetValue<string>());
            jsonObject.Add("Username", secret["Username"]?.GetValue<string>() ?? "");
            jsonObject.Add("FolderPath", secret["FolderPath"]?.GetValue<string>());
            jsonObject.Add("FilePath", filePath);
            jsonObject.Add("IsFileSecret", true);
            return jsonObject;
        }

        public static JsonObject convertSecretToObject(JsonObject secret)
        {
            JsonObject jsonObject = new JsonObject();
            jsonObject.Add("Password", secret["Password"]?.GetValue<string>());
            jsonObject.Add("Title", secret["Title"]?.GetValue<string>());
            jsonObject.Add("Username", secret["Username"]?.GetValue<string>() ?? "");
            jsonObject.Add("FolderPath", secret["FolderPath"]?.GetValue<string>());
            jsonObject.Add("FilePath", "");
            jsonObject.Add("IsFileSecret", false);
            return jsonObject;
        }

        public static JsonObject convertManagedAccountToObject(JsonObject secret, String content)
        {
            JsonObject jsonObject = new JsonObject();
            jsonObject.Add("Password", content);
            jsonObject.Add("SystemName", secret["SystemName"]?.GetValue<string>());
            jsonObject.Add("AccountName", secret["AccountName"]?.GetValue<string>());
            jsonObject.Add("FolderPath", secret["SystemName"]?.GetValue<string>() + "/" + secret["AccountName"]?.GetValue<string>());
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
