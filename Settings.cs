using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace BeyondInsight
{
    internal class Settings
    {
        public static String BT_API_URL = Environment.GetEnvironmentVariable("BT_API_URL");
        public static String REQUEST_HEADERS = "PS-Auth key=" + Environment.GetEnvironmentVariable("BT_API_KEY");
        public static bool FETCH_ALL_MANAGED_ACCOUNTS = bool.TryParse(GetEnvironmentVariable("FETCH_ALL_MANAGED_ACCOUNTS", "false"), out var result) && result;

        public static String APP_PATH = "/usr/src/app";
        public static String DEFAULT_SECRETS_FOLDER = "secrets_files";
        public static String SECRETS_PATH = APP_PATH + "/" + DEFAULT_SECRETS_FOLDER;

        static Settings()
        {
            String secretsPath = Environment.GetEnvironmentVariable("SECRETS_PATH");
            if (!string.IsNullOrWhiteSpace(secretsPath))
            {
                SECRETS_PATH = secretsPath;
            }
        }

        public static String SECRETS_LIST = GetEnvironmentVariable("SECRETS_LIST", "");
        public static String FOLDER_LIST = GetEnvironmentVariable("FOLDER_LIST", "");
        public static String MANAGED_ACCOUNTS_LIST = GetEnvironmentVariable("MANAGED_ACCOUNTS_LIST", "");


        public static String BT_CLIENT_CERTIFICATE = Environment.GetEnvironmentVariable("BT_CLIENT_CERTIFICATE");

        public static String EXCECUTION_ID = null;
        public static String APP_VERSION = "2.0.0";


        public static string GetEnvironmentVariable(string key, string defaultValue)
        {
            var value = Environment.GetEnvironmentVariable(key);
            return value ?? defaultValue;
        }
    }
}
