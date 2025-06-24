using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Threading.Tasks;


namespace BeyondInsight
{
    public class BeyondInsight
    {
        public static JObject getSecrets()
        {
            Utils.log("APP VERSION: " + Settings.APP_VERSION, LogLevel.Information);
            Utils.log("Starting Execution..." + Settings.EXCECUTION_ID, LogLevel.Information);
            Utils.log("Getting secrets..", LogLevel.Information);

            
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
                    JObject secrets = getSecretsFromBT(secretList, folderList, managedAccountList);
                    Utils.log("Execution Ended." + Settings.EXCECUTION_ID, LogLevel.Information);
                    if (!Service.signAppOut().Result)
                    {
                        throw new Exception("Sign out failed");
                    }
                    return secrets;
                } else
                {
                    Utils.log("Sign in failed", LogLevel.Error);
                }
            } catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Detail: " + ex.ToString());
            }


            return null;
        }


        public static JObject getSecretsFromBT(String secretList, String folderList, String managedAccountList)
        {
            JArray secrets = new JArray();
            try {
                if (!String.IsNullOrWhiteSpace(secretList) || !String.IsNullOrWhiteSpace(folderList))
                {
                    secrets = getSecretsByFolderPathOrSecretPath(secretList, folderList);
                }
                if (Settings.FETCH_ALL_MANAGED_ACCOUNTS)
                {
                    String[] managedAccounts = getManagedAccounts();
                    JArray managedSecrets = getSecretsBySystemNameAndAccountName(managedAccounts);
                    secrets = joinSecrets(secrets, managedSecrets);
                } else if (!String.IsNullOrWhiteSpace(managedAccountList))
                {
                    JArray managedSecrets = getSecretsBySystemNameAndAccountName(managedAccountList.Split(','));
                    secrets = joinSecrets(secrets, managedSecrets);
                }

                JObject result = generateSecretJSONObject(secrets);
                return result;

            } catch (Exception ex) {
                Utils.log(string.Format("Error: {0}", ex.Message), LogLevel.Error);
            }
            return null;
        }

        public static JArray getSecretsBySystemNameAndAccountName(String[] managedAccounts)
        {
            JArray secrets = new JArray();
            foreach (String manageAccount in managedAccounts)
            {
                string[] data = manageAccount.Trim().Split('/');
                if (data.Length != 2)
                {
                    Utils.log(string.Format("Invalid Managed Account: {0}", manageAccount.Trim()), LogLevel.Error);
                    continue;
                }
                String systemName = data[0];
                String accountName = data[1];

                String secretPath = systemName + "/" + accountName;
                String response = Service.getManagedAccounts(systemName, accountName).Result;
                if (String.IsNullOrEmpty(response) || response.Equals("Managed Account not found"))
                {
                    Utils.log(String.Format("Invalid Managed Account: {0}", secretPath), LogLevel.Error);
                    continue;
                }
                JObject jsonObject = JObject.Parse(response);
                int systemID = jsonObject.Value<int>("SystemId");
                int accountID = jsonObject.Value<int>("AccountId");
                String requestID = Service.createRequestInPasswordSafe(systemID, accountID).Result;
                String credential = Service.getCredentialByRequestID(requestID).Result;
                secrets.Add(Utils.convertManagedAccountToObject(jsonObject, credential));
            }
            
            return secrets;
        }

        public static JArray getSecretsByFolderPathOrSecretPath(String secretsBySecretPath, String secretsByFolderPath)
        {
            JArray secrets = new JArray();
            char separator = '/';


            if (secretsBySecretPath != null && !String.IsNullOrEmpty(secretsBySecretPath))
            {
                String[] paths = secretsBySecretPath.Split(',');
                foreach (String secretPath in paths)
                {
                    if (String.IsNullOrWhiteSpace(secretPath)) continue;

                    String[] foldersInPath = secretPath.Trim().Split(separator);
                    String title = foldersInPath[foldersInPath.Length - 1];
                    string path = string.Join(separator.ToString(), foldersInPath.Take(foldersInPath.Length - 1));

                    String response = Service.getSecretByPath(path, title, separator, true).Result;
                    if (response.Length <= 2)
                    {
                        Utils.log(string.Format("Secret {0}/{1} was not Found, Validating Folder: {2}", path, title, string.Join(", ", foldersInPath)), LogLevel.Information);
                        response = Service.getSecretByPath(string.Join(separator.ToString(), foldersInPath), title, separator, false).Result;
                        if (response.Length <= 2)
                        {
                            Utils.log(string.Format("Invalid path or Invalid Secret: {0}", secretPath), LogLevel.Error);
                            continue;
                        }
                        JArray jsonArray = JArray.Parse(response);
                        for (int i = 0; i < jsonArray.Count; i++)
                        {
                            JObject jsonObject = (JObject)jsonArray[i];

                            JObject secret = get_secrets_in_folder(jsonObject);
                            if (secret != null)
                            {
                                secrets.Add(secret);
                            }

                        }
                    } else
                    {
                        JArray jsonArray = JArray.Parse(response);
                        for (int i = 0;i < jsonArray.Count; i++)
                        {
                            JObject jsonObject = (JObject)jsonArray[i];
                            if (jsonObject.Value<string>("SecretType").Equals("File"))
                            {
                                String fileContent = Service.getSecretFilebyId(jsonObject.Value<string>("Id")).Result;
                                if (!String.IsNullOrEmpty(fileContent))
                                {
                                    JObject secret = Utils.createSecretFile(jsonObject, fileContent);
                                    if (secret != null)
                                    {
                                        secrets.Add(secret);
                                    }
                                } else
                                {
                                    Utils.log(string.Format("Error Getting File secret, secret metadata: {0}", jsonObject.ToString()), LogLevel.Error);
                                    continue;
                                }
                            } else
                            {
                                JObject secret = Utils.convertSecretToObject(jsonObject);
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
                String[] folders = secretsByFolderPath.Split(',');
                Utils.log(string.Format("Getting secrets by folders {0}", string.Join(", ", folders)), LogLevel.Information);
                foreach (String folder in folders)
                {
                    String response = Service.getSecretByPath(folder, "", separator, false).Result;
                    if (response.Length <= 2)
                    {
                        Utils.log(string.Format("Invalid path or Invalid Secret: {0}", folder), LogLevel.Error);
                        continue;
                    }
                    JArray jsonArray = JArray.Parse(response);
                    for(int i = 0; i < jsonArray.Count; i++)
                    {
                        JObject jsonObject = (JObject)jsonArray[i];
                        JObject secret = get_secrets_in_folder(jsonObject);
                        if (secret != null)
                        {
                            secrets.Add(secret);
                        }
                    }
                }
            }
            return secrets;
        }

        public static JObject get_secrets_in_folder(JObject secret)
        {
            if ("File".Equals(secret.Value<string>("SecretType")))
            {
                String fileContent = Service.getSecretFilebyId(secret.Value<string>("Id")).Result;
                if (!String.IsNullOrEmpty(fileContent))
                {
                    return Utils.createSecretFile(secret, fileContent);
                } else
                {
                    Utils.log(string.Format("Error Getting File secret, secret metadata: {0}", secret), LogLevel.Error);
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
            JArray jsonArray = JArray.Parse(response);
            String[] managedAccounts = new String[jsonArray.Count];
            for (int i = 0; i < jsonArray.Count; i++)
            {
                JObject jsonObject = (JObject)jsonArray[i];
                managedAccounts[i] = jsonObject.Value<string>("SystemName") + "/" + jsonObject.Value<string>("AccountName");
            }
            return managedAccounts;
        }

        public static JObject generateSecretJSONObject(JArray jsonArray)
        {
            JObject result = new JObject();
            foreach (JObject item in jsonArray)
            {
                String folderPath = item["FolderPath"]?.ToString();
                String[] folders = folderPath.Split(',');

                JObject current = result;
                for (int i = 0;i < folders.Length;i++)
                {
                    String folder = folders[i];
                    if (!current.ContainsKey(folder))
                    {
                        if (item.ContainsKey("AccountName") && folder == folders[folders.Count() -1 ])
                        {
                            string accountName = item["AccountName"]?.ToString() ?? "";
                            current[accountName] = JObject.Parse(item.ToString());
                        } else
                        {
                            current[folder] = new JObject();
                        }
                    }
                    if (current[folder] is JObject nested)
                    {
                        current = nested;
                    }
                }
                if (item.ContainsKey("Title"))
                {
                    string title = item["Title"]?.ToString() ?? "";
                    JObject temp = item;
                    if (!current.ContainsKey(title))
                    {
                        current[title] = JObject.Parse(item.ToString());
                    }
                }
            }
            return result;
        }

        public static JArray joinSecrets(JArray secrets, JArray secrets2)
        {
            
            foreach (JObject secret in secrets2)
            {
                secrets.Add(secret.DeepClone());
            }
            return secrets;
        }
    }
}
