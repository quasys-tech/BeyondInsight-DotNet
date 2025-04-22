using System;
using System.Linq;
using System.Reflection.Emit;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace BeyondInsight
{
    public class BeyondInsight
    {
        public static JsonObject getSecrets()
        {
            Utils.log("APP VERSION: " + Settings.APP_VERSION, Microsoft.Extensions.Logging.LogLevel.Information);
            Utils.log("Starting Execution..." + Settings.EXCECUTION_ID, Microsoft.Extensions.Logging.LogLevel.Information);
            Utils.log("Getting secrets..", Microsoft.Extensions.Logging.LogLevel.Information);

            
            String secretList = Settings.SECRETS_LIST.ToLower();
            String folderList = Settings.FOLDER_LIST.ToLower();
            String managedAccountList = Settings.MANAGED_ACCOUNTS_LIST.ToLower();

            /*Console.WriteLine(String.IsNullOrWhiteSpace(secretList));
            Console.WriteLine(String.IsNullOrWhiteSpace(folderList));
            Console.WriteLine(String.IsNullOrWhiteSpace(managedAccountList));*/

            try
            {

                if (String.IsNullOrWhiteSpace(Settings.BT_API_URL))
                {
                    throw new Exception("BT_API_URL is empty!");
                }
                if (String.IsNullOrWhiteSpace(Settings.BT_CLIENT_CERTIFICATE))
                {
                    throw new Exception("BT_CLIENT_CERTIFICATE is empty!");
                }

                Task<String> user = Service.SignAppIn();
                Console.WriteLine(user.Result);


                if (user != null)
                {
                    JsonObject secrets = getSecretsFromBT(secretList, folderList, managedAccountList);
                    Utils.log("Execution Ended." + Settings.EXCECUTION_ID, Microsoft.Extensions.Logging.LogLevel.Information);
                    if (!Service.signAppOut().Result)
                    {
                        throw new Exception("Sign out failed");
                    }
                    return secrets;
                } else
                {
                    Utils.log("Sign in failed", Microsoft.Extensions.Logging.LogLevel.Error);
                }
            } catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Detail: " + ex.ToString());
            }


            return null;
        }


        public static JsonObject getSecretsFromBT(String secretList, String folderList, String managedAccountList)
        {
            JsonArray secrets = new JsonArray();
            try {
                if (!String.IsNullOrWhiteSpace(secretList) || !String.IsNullOrWhiteSpace(folderList))
                {
                    secrets = getSecretsByFolderPathOrSecretPath(secretList, folderList);
                }
                if (Settings.FETCH_ALL_MANAGED_ACCOUNTS)
                {
                    String[] managedAccounts = getManagedAccounts();
                    JsonArray managedSecrets = getSecretsBySystemNameAndAccountName(managedAccounts);
                    secrets = joinSecrets(secrets, managedSecrets);
                } else if (!String.IsNullOrWhiteSpace(managedAccountList))
                {
                    JsonArray managedSecrets = getSecretsBySystemNameAndAccountName(managedAccountList.Split(','));
                    secrets = joinSecrets(secrets, managedSecrets);
                }

                JsonObject result = generateSecretJSONObject(secrets);
                return result;

            } catch (Exception ex) {
                Utils.log(string.Format("Error: {0}", ex.Message), Microsoft.Extensions.Logging.LogLevel.Error);
            }
            return null;
        }

        public static JsonArray getSecretsBySystemNameAndAccountName(String[] managedAccounts)
        {
            JsonArray secrets = new JsonArray();
            foreach (String manageAccount in managedAccounts)
            {
                string[] data = manageAccount.Trim().Split('/');
                if (data.Length != 2)
                {
                    Utils.log(string.Format("Invalid Managed Account: {0}", manageAccount.Trim()), Microsoft.Extensions.Logging.LogLevel.Error);
                    continue;
                }
                String systemName = data[0];
                String accountName = data[1];

                String secretPath = systemName + "/" + accountName;
                String response = Service.getManagedAccounts(systemName, accountName).Result;
                if (String.IsNullOrEmpty(response) || response.Equals("Managed Account not found"))
                {
                    Utils.log(String.Format("Invalid Managed Account: {0}", secretPath), Microsoft.Extensions.Logging.LogLevel.Error);
                    continue;
                }
                JsonObject jsonObject = JsonNode.Parse(response).AsObject();
                int systemID = jsonObject["SystemId"].GetValue<int>();
                int accountID = jsonObject["AccountId"].GetValue<int>();
                String requestID = Service.createRequestInPasswordSafe(systemID, accountID).Result;
                String credential = Service.getCredentialByRequestID(requestID).Result;
                secrets.Add(Utils.convertManagedAccountToObject(jsonObject, credential));
            }
            
            return secrets;
        }

        public static JsonArray getSecretsByFolderPathOrSecretPath(String secretsBySecretPath, String secretsByFolderPath)
        {
            JsonArray secrets = new JsonArray();
            char separator = '/';


            if (secretsBySecretPath != null && !String.IsNullOrEmpty(secretsBySecretPath))
            {
                String[] paths = secretsBySecretPath.Split(',');
                foreach (String secretPath in paths)
                {
                    if (String.IsNullOrWhiteSpace(secretPath)) continue;

                    String[] foldersInPath = secretPath.Trim().Split(separator);
                    String title = foldersInPath[foldersInPath.Length - 1];
                    string path = string.Join(separator, foldersInPath.Take(foldersInPath.Length - 1));

                    String response = Service.getSecretByPath(path, title, separator, true).Result;
                    if (response.Length <= 2)
                    {
                        Utils.log(string.Format("Secret {0}/{1} was not Found, Validating Folder: {2}", path, title, string.Join(", ", foldersInPath)), Microsoft.Extensions.Logging.LogLevel.Information);
                        response = Service.getSecretByPath(string.Join(separator, foldersInPath), title, separator, false).Result;
                        if (response.Length <= 2)
                        {
                            Utils.log(string.Format("Invalid path or Invalid Secret: {0}", secretPath), Microsoft.Extensions.Logging.LogLevel.Error);
                            continue;
                        }
                        JsonArray jsonArray = JsonNode.Parse(response).AsArray();
                        for (int i = 0; i < jsonArray.Count; i++)
                        {
                            JsonObject jsonObject = jsonArray[i].AsObject();

                            JsonObject secret = get_secrets_in_folder(jsonObject);
                            if (secret != null)
                            {
                                secrets.Add(secret);
                            }

                        }
                    } else
                    {
                        JsonArray jsonArray = JsonNode.Parse(response).AsArray();
                        for (int i = 0;i < jsonArray.Count; i++)
                        {
                            JsonObject jsonObject = jsonArray[i].AsObject();
                            if (jsonObject["SecretType"].GetValue<string>().Equals("File"))
                            {
                                String fileContent = Service.getSecretFilebyId(jsonObject["Id"].GetValue<string>()).Result;
                                if (!String.IsNullOrEmpty(fileContent))
                                {
                                    JsonObject secret = Utils.createSecretFile(jsonObject, fileContent);
                                    if (secret != null)
                                    {
                                        secrets.Add(secret);
                                    }
                                } else
                                {
                                    Utils.log(string.Format("Error Getting File secret, secret metadata: {0}", jsonObject.ToString()), Microsoft.Extensions.Logging.LogLevel.Error);
                                    continue;
                                }
                            } else
                            {
                                JsonObject secret = Utils.convertSecretToObject(jsonObject);
                                if (secret != null)
                                {
                                    secrets.Add(secret);
                                }
                            }
                        }
                    }
                }
            }

            if (secretsByFolderPath != null && !String.IsNullOrEmpty(secretsByFolderPath))
            {
                String[] folders = secretsByFolderPath.Split(",");
                Utils.log(string.Format("Getting secrets by folders {0}", string.Join(", ", folders)), Microsoft.Extensions.Logging.LogLevel.Information);
                foreach (String folder in folders)
                {
                    String response = Service.getSecretByPath(folder, "", separator, false).Result;
                    if (response.Length <= 2)
                    {
                        Utils.log(string.Format("Invalid path or Invalid Secret: {0}", folder), Microsoft.Extensions.Logging.LogLevel.Error);
                        continue;
                    }
                    JsonArray jsonArray = JsonNode.Parse(response).AsArray();
                    for(int i = 0; i < jsonArray.Count; i++)
                    {
                        JsonObject jsonObject = jsonArray[i].AsObject();
                        JsonObject secret = get_secrets_in_folder(jsonObject);
                        if (secret != null)
                        {
                            secrets.Add(secret);
                        }
                    }
                }
            }
            return secrets;
        }

        public static JsonObject get_secrets_in_folder(JsonObject secret)
        {
            if ("File".Equals(secret["SecretType"].GetValue<string>()))
            {
                String fileContent = Service.getSecretFilebyId(secret["Id"].GetValue<string>()).Result;
                if (!String.IsNullOrEmpty(fileContent))
                {
                    return Utils.createSecretFile(secret, fileContent);
                } else
                {
                    Utils.log(string.Format("Error Getting File secret, secret metadata: {0}", secret), Microsoft.Extensions.Logging.LogLevel.Error);
                    return null;
                }
            } else
            {
                return Utils.convertSecretToObject(secret);
            }
        }

        public static String[] getManagedAccounts()
        {
            char separator  = '/';
            String response = Service.getManagedAccounts("", "").Result;
            JsonArray jsonArray = JsonNode.Parse(response).AsArray();
            String[] managedAccounts = new String[jsonArray.Count];
            for (int i = 0; i < jsonArray.Count; i++)
            {
                JsonObject jsonObject = jsonArray[i].AsObject();
                managedAccounts[i] = jsonObject["SystemName"].GetValue<string>() + "/" + jsonObject["AccountName"].GetValue<string>();
            }
            return managedAccounts;
        }

        public static JsonObject generateSecretJSONObject(JsonArray jsonArray)
        {
            JsonObject result = new JsonObject();
            foreach (JsonObject item in jsonArray)
            {
                String folderPath = item["FolderPath"].GetValue<string>();
                String[] folders = folderPath.Split("/");

                JsonObject current = result;
                for (int i = 0;i < folders.Length;i++)
                {
                    String folder = folders[i];
                    if (!current.ContainsKey(folder))
                    {
                        if (item.ContainsKey("AccountName") && folder == folders[^1])
                        {
                            current.Insert(0, item["AccountName"].GetValue<string>(), JsonNode.Parse(item.ToString()));
                        } else
                        {
                            current[folder] = new JsonObject();
                        }
                    }
                    current = current[folder].AsObject();
                }
                if (item.ContainsKey("Title"))
                {
                    string title = item["Title"]?.ToString() ?? "";
                    JsonObject temp = item;
                    if (!current.ContainsKey(title))
                    {
                        current.Insert(0, title, JsonNode.Parse(item.ToString()));
                    }
                }
            }
            return result;
        }

        public static JsonArray joinSecrets(JsonArray secrets, JsonArray secrets2)
        {
            
            foreach (JsonObject secret in secrets2)
            {
                secrets.Add(secret.DeepClone());
            }
            return secrets;
        }
    }
}
