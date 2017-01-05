//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

//
// This source code was auto-generated by cf-sdk-builder
//

using CloudFoundry.CloudController.V2.Client;
using CloudFoundry.CloudController.V2.Client.Data;
using Microsoft.CSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.CodeDom.Compiler;

namespace CloudFoundry.CloudController.V2.Test.Deserialization
{
    [TestClass]
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public class JobsTest
    {


        [TestMethod]
        public void TestRetrieveJobWithKnownFailureResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""c0b3c5ce-2ab9-472b-bba0-b060b082e27f"",
    ""created_at"": ""2017-01-04T15:59:08Z"",
    ""url"": ""/v2/jobs/56dc1a2c-88d1-46cf-a770-8bab5f2e98bf""
  },
  ""entity"": {
    ""guid"": ""c0b3c5ce-2ab9-472b-bba0-b060b082e27f"",
    ""status"": ""failed"",
    ""error"": ""Use of entity>error is deprecated in favor of entity>error_details."",
    ""error_details"": {
      ""code"": 1001,
      ""description"": ""Request invalid due to parse error: arbitrary string"",
      ""error_code"": ""CF-MessageParseError""
    }
  }
}";

            RetrieveJobWithKnownFailureResponse obj = Utilities.DeserializeJson<RetrieveJobWithKnownFailureResponse>(json);

            Assert.AreEqual("c0b3c5ce-2ab9-472b-bba0-b060b082e27f", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("2017-01-04T15:59:08Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("/v2/jobs/56dc1a2c-88d1-46cf-a770-8bab5f2e98bf", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("c0b3c5ce-2ab9-472b-bba0-b060b082e27f", TestUtil.ToTestableString(obj.Guid), true);
            Assert.AreEqual("failed", TestUtil.ToTestableString(obj.Status), true);
            Assert.AreEqual("Use of entity>error is deprecated in favor of entity>error_details.", TestUtil.ToTestableString(obj.Error), true);
        }

        [TestMethod]
        public void TestRetrieveJobWithUnknownFailureResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""e9cab0ef-293f-49e2-a72d-4d0eaa20d5c5"",
    ""created_at"": ""2017-01-04T15:59:09Z"",
    ""url"": ""/v2/jobs/2a8bc9bb-0fac-4767-9393-b4dd7cd1cc76""
  },
  ""entity"": {
    ""guid"": ""e9cab0ef-293f-49e2-a72d-4d0eaa20d5c5"",
    ""status"": ""failed"",
    ""error"": ""Use of entity>error is deprecated in favor of entity>error_details."",
    ""error_details"": {
      ""error_code"": ""UnknownError"",
      ""description"": ""An unknown error occurred."",
      ""code"": 10001
    }
  }
}";

            RetrieveJobWithUnknownFailureResponse obj = Utilities.DeserializeJson<RetrieveJobWithUnknownFailureResponse>(json);

            Assert.AreEqual("e9cab0ef-293f-49e2-a72d-4d0eaa20d5c5", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("2017-01-04T15:59:09Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("/v2/jobs/2a8bc9bb-0fac-4767-9393-b4dd7cd1cc76", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("e9cab0ef-293f-49e2-a72d-4d0eaa20d5c5", TestUtil.ToTestableString(obj.Guid), true);
            Assert.AreEqual("failed", TestUtil.ToTestableString(obj.Status), true);
            Assert.AreEqual("Use of entity>error is deprecated in favor of entity>error_details.", TestUtil.ToTestableString(obj.Error), true);
        }

        [TestMethod]
        public void TestRetrieveJobThatIsQueuedResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""7f6f10bd-2f40-4433-8a78-f11408ea9311"",
    ""created_at"": ""2017-01-04T15:59:08Z"",
    ""url"": ""/v2/jobs/484ff707-4d25-40f6-aa52-d2bea73edf88""
  },
  ""entity"": {
    ""guid"": ""7f6f10bd-2f40-4433-8a78-f11408ea9311"",
    ""status"": ""queued""
  }
}";

            RetrieveJobThatIsQueuedResponse obj = Utilities.DeserializeJson<RetrieveJobThatIsQueuedResponse>(json);

            Assert.AreEqual("7f6f10bd-2f40-4433-8a78-f11408ea9311", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("2017-01-04T15:59:08Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("/v2/jobs/484ff707-4d25-40f6-aa52-d2bea73edf88", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("7f6f10bd-2f40-4433-8a78-f11408ea9311", TestUtil.ToTestableString(obj.Guid), true);
            Assert.AreEqual("queued", TestUtil.ToTestableString(obj.Status), true);
        }

        [TestMethod]
        public void TestRetrieveJobThatWasSuccessfulResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""9f7a8d9f-237b-44d0-9384-66606b6c684b"",
    ""created_at"": ""1970-01-01T00:00:00Z"",
    ""url"": ""/v2/jobs/0""
  },
  ""entity"": {
    ""guid"": ""9f7a8d9f-237b-44d0-9384-66606b6c684b"",
    ""status"": ""finished""
  }
}";

            RetrieveJobThatWasSuccessfulResponse obj = Utilities.DeserializeJson<RetrieveJobThatWasSuccessfulResponse>(json);

            Assert.AreEqual("9f7a8d9f-237b-44d0-9384-66606b6c684b", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("1970-01-01T00:00:00Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("/v2/jobs/0", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("9f7a8d9f-237b-44d0-9384-66606b6c684b", TestUtil.ToTestableString(obj.Guid), true);
            Assert.AreEqual("finished", TestUtil.ToTestableString(obj.Status), true);
        }
    }
}
