using BeyondInsight;
using Newtonsoft.Json.Linq;

namespace Beyond.Tests
{
    public class Tests
    {
        private string _tempFolder;
        private string _tempSecretsPath;


        [SetUp]
        public void Setup()
        {
            _tempFolder = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempFolder);

            _tempSecretsPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempSecretsPath);


            Settings.SECRETS_PATH = _tempSecretsPath;
        }

        [TearDown]
        public void Cleanup()
        {
            if (Directory.Exists(_tempFolder))
                Directory.Delete(_tempFolder, true);
            if (Directory.Exists(_tempSecretsPath))
                Directory.Delete(_tempSecretsPath, true);
        }

        [Test]
        public void createSecretFile_CreatesFileAndReturnsCorrectJObject()
        {
            var secret = new JObject
        {
            { "FolderPath", _tempFolder },
            { "Title", "mysecret.txt" },
            { "Password", "1234" },
            { "Username", "admin" }
        };
            string content = "This is a test secret";

            // Act
            var result = BeyondInsight.Utils.createSecretFile(secret, content);

            // Assert
            string expectedFilePath = Path.Combine(_tempFolder, "mysecret.txt");
            Assert.IsTrue(File.Exists(expectedFilePath), "Dosya oluşturulamadı.");

            var fileContent = File.ReadAllText(expectedFilePath);
            Assert.AreEqual(content + "\n", fileContent, "Dosya içeriği uyuşmuyor.");

            Assert.AreEqual("1234", result["Password"].ToString());
            Assert.AreEqual("admin", result["Username"].ToString());
            Assert.AreEqual("mysecret.txt", result["Title"].ToString());
            Assert.AreEqual(_tempFolder, result["FolderPath"].ToString());
            Assert.AreEqual(Path.GetFullPath(expectedFilePath), Path.GetFullPath((string)result["FilePath"]));
            Assert.AreEqual("True", result["IsFileSecret"].ToString());
            Assert.Pass();
        }

        [Test]
        public void convertSecretToObject_ShouldReturnExpectedJObject_WhenAllFieldsArePresent()
        {
            // Arrange
            var input = new JObject
        {
            { "Password", "mypassword" },
            { "Title", "MySecret" },
            { "Username", "myuser" },
            { "FolderPath", "/my/path" }
        };

            // Act
            var result = BeyondInsight.Utils.convertSecretToObject(input);

            // Assert
            Assert.AreEqual("mypassword", result["Password"].ToString());
            Assert.AreEqual("MySecret", result["Title"].ToString());
            Assert.AreEqual("myuser", result["Username"].ToString());
            Assert.AreEqual("/my/path", result["FolderPath"].ToString());
            Assert.AreEqual("", result["FilePath"].ToString());
            Assert.AreEqual("False", result["IsFileSecret"].ToString());
        }

        [Test]
        public void convertSecretToObject_ShouldAssignEmptyUsername_WhenUsernameIsNull()
        {
            // Arrange
            var input = new JObject
        {
            { "Password", "pass123" },
            { "Title", "Title1" },
            { "Username", null }, // explicitly null
            { "FolderPath", "/folder" }
        };

            // Act
            var result = BeyondInsight.Utils.convertSecretToObject(input);

            // Assert
            Assert.AreEqual("", result["Username"].ToString());
        }

        [Test]
        public void convertSecretToObject_ShouldHandleMissingFields_Gracefully()
        {
            // Arrange
            var input = new JObject(); // tüm alanlar eksik

            // Act
            var result = BeyondInsight.Utils.convertSecretToObject(input);

            // Assert
            Assert.IsEmpty(result["Password"]);
            Assert.IsEmpty(result["Title"]);
            Assert.AreEqual("", result["Username"].ToString());
            Assert.IsEmpty(result["FolderPath"]);
            Assert.AreEqual("", result["FilePath"].ToString());
            Assert.AreEqual("False", result["IsFileSecret"].ToString());
        }


        [Test]
        public void convertManagedAccountToObject_ReturnsExpectedJObject()
        {
            // Arrange
            var secret = new JObject
        {
            { "SystemName", "MySystem" },
            { "AccountName", "MyAccount" }
        };

            string content = "securepassword123";

            // Act
            var result = BeyondInsight.Utils.convertManagedAccountToObject(secret, content);

            // Assert
            Assert.AreEqual("securepassword123", result["Password"].ToString());
            Assert.AreEqual("MySystem", result["SystemName"].ToString());
            Assert.AreEqual("MyAccount", result["AccountName"].ToString());
            Assert.AreEqual("MySystem/MyAccount", result["FolderPath"].ToString());
            Assert.AreEqual("False", result["IsFileSecret"].ToString());
        }

        [Test]
        public void convertManagedAccountToObject_HandlesMissingValuesGracefully()
        {
            // Arrange
            var secret = new JObject(); // Eksik alanlar

            string content = "somepass";

            // Act
            var result = BeyondInsight.Utils.convertManagedAccountToObject(secret, content);

            // Assert
            Assert.AreEqual("somepass", result["Password"].ToString());
            Assert.IsEmpty(result["SystemName"]);
            Assert.IsEmpty(result["AccountName"]);
            Assert.AreEqual("/", result["FolderPath"].ToString());
            Assert.AreEqual("False", result["IsFileSecret"].ToString());
        }


        [Test]
        public void createFolders_CreatesParentDirectoryAndReturnsFullPath()
        {
            // Arrange
            string relativePath = "folder1/folder2/file.txt";
            string expectedFullPath = Path.Combine(_tempSecretsPath, relativePath);
            string expectedDirectory = Path.GetDirectoryName(expectedFullPath);

            // Act
            string result = BeyondInsight.Utils.createFolders(relativePath);

            // Assert
            Assert.AreEqual(expectedFullPath, result);
            Assert.IsTrue(Directory.Exists(expectedDirectory), "Parent klasör oluşturulmadı.");
        }

        [Test]
        public void createFolders_DoesNotThrow_WhenDirectoryAlreadyExists()
        {
            // Arrange
            string relativePath = "existing/dir/file.txt";
            string fullPath = Path.Combine(_tempSecretsPath, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath));

            // Act
            string result = BeyondInsight.Utils.createFolders(relativePath);

            // Assert
            Assert.AreEqual(fullPath, result);
            Assert.IsTrue(Directory.Exists(Path.GetDirectoryName(fullPath)));
        }
    }
}