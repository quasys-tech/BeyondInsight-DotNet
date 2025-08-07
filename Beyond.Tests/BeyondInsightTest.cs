using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Beyond.Tests
{
    public class BeyondInsightTest
    {
        [Test]
        public void joinSecrets_MergesTwoArraysCorrectly_WithDeepClone()
        {
            // Arrange
            var secrets = new JArray
        {
            new JObject { { "Title", "Secret1" }, { "Value", "abc" } }
        };

            var secrets2 = new JArray
        {
            new JObject { { "Title", "Secret2" }, { "Value", "def" } },
            new JObject { { "Title", "Secret3" }, { "Value", "ghi" } }
        };

            // Act
            var result = BeyondInsight.BeyondInsight.joinSecrets(secrets, secrets2);

            // Assert: Toplam 3 öğe olmalı
            Assert.AreEqual(3, result.Count);

            // Assert: Orijinal secrets2 değişmemiş olmalı
            Assert.AreEqual(2, secrets2.Count);
            Assert.AreEqual("Secret2", secrets2[0]["Title"].ToString());
            Assert.AreEqual("Secret3", secrets2[1]["Title"].ToString());

            // Assert: Eklenen nesneler deep clone yapılmış (referans farklı)
            Assert.AreNotSame(secrets2[0], result[1]);
            Assert.AreEqual(secrets2[0].ToString(), result[1].ToString());

            // Assert: İlk secret değişmemiş
            Assert.AreEqual("Secret1", result[0]["Title"].ToString());
        }

        [Test]
        public void joinSecrets_ReturnsSameReferenceAsSecrets()
        {
            // Arrange
            var secrets = new JArray();
            var secrets2 = new JArray { new JObject { { "Key", "Value" } } };

            // Act
            var result = BeyondInsight.BeyondInsight.joinSecrets(secrets, secrets2);

            // Assert: Aynı referans dönmeli
            Assert.AreSame(secrets, result);
        }


        [Test]
        public void generateSecretJSONObject_CreatesCorrectNestedStructure()
        {
            // Arrange
            var jsonArray = new JArray
        {
            new JObject
            {
                { "FolderPath", "Finance,Payroll" },
                { "Title", "PayrollSecret" },
                { "Password", "123" }
            }
        };

            // Act
            var result = BeyondInsight.BeyondInsight.generateSecretJSONObject(jsonArray);

            // Assert
            Assert.IsTrue(result.ContainsKey("Finance"));
            Assert.IsTrue(result["Finance"]["Payroll"] is JObject);

            var nested = (JObject)result["Finance"]["Payroll"];
            Assert.IsTrue(nested.ContainsKey("PayrollSecret"));

            var secret = (JObject)nested["PayrollSecret"];
            Assert.AreEqual("123", secret["Password"].ToString());
        }



        [Test]
        public void generateSecretJSONObject_CanHandleMultipleSecretsInSamePath()
        {
            // Arrange
            var jsonArray = new JArray
        {
            new JObject
            {
                { "FolderPath", "Dev,API" },
                { "Title", "ApiKey1" },
                { "Password", "key1" }
            },
            new JObject
            {
                { "FolderPath", "Dev,API" },
                { "Title", "ApiKey2" },
                { "Password", "key2" }
            }
        };

            // Act
            var result = BeyondInsight.BeyondInsight.generateSecretJSONObject(jsonArray);

            // Assert
            var path = (JObject)result["Dev"]["API"];
            Assert.IsTrue(path.ContainsKey("ApiKey1"));
            Assert.IsTrue(path.ContainsKey("ApiKey2"));
        }
    }
}
