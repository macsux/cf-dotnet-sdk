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
    public class BuildpacksTest
    {


        [TestMethod]
        public void TestListAllBuildpacksResponse()
        {
            string json = @"{
  ""total_results"": 3,
  ""total_pages"": 1,
  ""prev_url"": null,
  ""next_url"": null,
  ""resources"": [
    {
      ""metadata"": {
        ""guid"": ""22baf631-bc29-4015-b3b5-e430b3138898"",
        ""url"": ""/v2/buildpacks/5f0b67c7-7c80-47cb-9a93-74834f0c64e8"",
        ""created_at"": ""2016-03-30T10:15:09Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name_1"",
        ""position"": 1,
        ""enabled"": true,
        ""locked"": false,
        ""filename"": ""name-173""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""22baf631-bc29-4015-b3b5-e430b3138898"",
        ""url"": ""/v2/buildpacks/6bf5d866-5f4e-49e4-87e0-f8d741e5ce63"",
        ""created_at"": ""2016-03-30T10:15:09Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name_2"",
        ""position"": 2,
        ""enabled"": true,
        ""locked"": false,
        ""filename"": ""name-174""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""22baf631-bc29-4015-b3b5-e430b3138898"",
        ""url"": ""/v2/buildpacks/546e3c47-14b7-4e9e-96b1-46f406d14c97"",
        ""created_at"": ""2016-03-30T10:15:09Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name_3"",
        ""position"": 3,
        ""enabled"": true,
        ""locked"": false,
        ""filename"": ""name-175""
      }
    }
  ]
}";

            PagedResponseCollection<ListAllBuildpacksResponse> page = Utilities.DeserializePage<ListAllBuildpacksResponse>(json, null);

            Assert.AreEqual("3", TestUtil.ToTestableString(page.Properties.TotalResults), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalPages), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.PreviousUrl), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.NextUrl), true);
            Assert.AreEqual("22baf631-bc29-4015-b3b5-e430b3138898", TestUtil.ToTestableString(page[0].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/5f0b67c7-7c80-47cb-9a93-74834f0c64e8", TestUtil.ToTestableString(page[0].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:09Z", TestUtil.ToTestableString(page[0].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_1", TestUtil.ToTestableString(page[0].Name), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(page[0].Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(page[0].Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[0].Locked), true);
            Assert.AreEqual("name-173", TestUtil.ToTestableString(page[0].Filename), true);
            Assert.AreEqual("22baf631-bc29-4015-b3b5-e430b3138898", TestUtil.ToTestableString(page[1].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/6bf5d866-5f4e-49e4-87e0-f8d741e5ce63", TestUtil.ToTestableString(page[1].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:09Z", TestUtil.ToTestableString(page[1].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[1].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_2", TestUtil.ToTestableString(page[1].Name), true);
            Assert.AreEqual("2", TestUtil.ToTestableString(page[1].Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(page[1].Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[1].Locked), true);
            Assert.AreEqual("name-174", TestUtil.ToTestableString(page[1].Filename), true);
            Assert.AreEqual("22baf631-bc29-4015-b3b5-e430b3138898", TestUtil.ToTestableString(page[2].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/546e3c47-14b7-4e9e-96b1-46f406d14c97", TestUtil.ToTestableString(page[2].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:09Z", TestUtil.ToTestableString(page[2].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[2].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_3", TestUtil.ToTestableString(page[2].Name), true);
            Assert.AreEqual("3", TestUtil.ToTestableString(page[2].Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(page[2].Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[2].Locked), true);
            Assert.AreEqual("name-175", TestUtil.ToTestableString(page[2].Filename), true);
        }

        [TestMethod]
        public void TestRetrieveBuildpackResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""2dab76d7-2e57-4f26-a496-2a2d00f1cc61"",
    ""url"": ""/v2/buildpacks/fd2501f6-678a-424f-9563-88d5fd562d00"",
    ""created_at"": ""2016-03-30T10:15:09Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""name"": ""name_1"",
    ""position"": 1,
    ""enabled"": true,
    ""locked"": false,
    ""filename"": ""name-170""
  }
}";

            RetrieveBuildpackResponse obj = Utilities.DeserializeJson<RetrieveBuildpackResponse>(json);

            Assert.AreEqual("2dab76d7-2e57-4f26-a496-2a2d00f1cc61", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/fd2501f6-678a-424f-9563-88d5fd562d00", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:09Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(obj.Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(obj.Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.Locked), true);
            Assert.AreEqual("name-170", TestUtil.ToTestableString(obj.Filename), true);
        }

        [TestMethod]
        public void TestChangePositionOfBuildpackResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""54563940-f74a-4917-b769-adbae1360a9f"",
    ""url"": ""/v2/buildpacks/c7361591-37cc-4a1e-bfa7-0c1f756d87ba"",
    ""created_at"": ""2016-03-30T10:15:08Z"",
    ""updated_at"": ""2016-03-30T10:15:08Z""
  },
  ""entity"": {
    ""name"": ""name_1"",
    ""position"": 3,
    ""enabled"": true,
    ""locked"": false,
    ""filename"": ""name-164""
  }
}";

            ChangePositionOfBuildpackResponse obj = Utilities.DeserializeJson<ChangePositionOfBuildpackResponse>(json);

            Assert.AreEqual("54563940-f74a-4917-b769-adbae1360a9f", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/c7361591-37cc-4a1e-bfa7-0c1f756d87ba", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("3", TestUtil.ToTestableString(obj.Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(obj.Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.Locked), true);
            Assert.AreEqual("name-164", TestUtil.ToTestableString(obj.Filename), true);
        }

        [TestMethod]
        public void TestCreatesAdminBuildpackResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""0fb287c6-9a39-435c-9ff5-7a59bd98fe3e"",
    ""url"": ""/v2/buildpacks/6cca5304-809a-4fc2-b4e8-cd094277b352"",
    ""created_at"": ""2016-03-30T10:15:09Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""name"": ""Golang_buildpack"",
    ""position"": 1,
    ""enabled"": true,
    ""locked"": false,
    ""filename"": null
  }
}";

            CreatesAdminBuildpackResponse obj = Utilities.DeserializeJson<CreatesAdminBuildpackResponse>(json);

            Assert.AreEqual("0fb287c6-9a39-435c-9ff5-7a59bd98fe3e", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/6cca5304-809a-4fc2-b4e8-cd094277b352", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:09Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("Golang_buildpack", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(obj.Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(obj.Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.Locked), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.Filename), true);
        }

        [TestMethod]
        public void TestLockOrUnlockBuildpackResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""2f066e60-966d-45f3-b489-8258473cb62b"",
    ""url"": ""/v2/buildpacks/3448718c-bfd5-427e-95a8-6a73041990c1"",
    ""created_at"": ""2016-03-30T10:15:08Z"",
    ""updated_at"": ""2016-03-30T10:15:08Z""
  },
  ""entity"": {
    ""name"": ""name_1"",
    ""position"": 1,
    ""enabled"": true,
    ""locked"": true,
    ""filename"": ""name-161""
  }
}";

            LockOrUnlockBuildpackResponse obj = Utilities.DeserializeJson<LockOrUnlockBuildpackResponse>(json);

            Assert.AreEqual("2f066e60-966d-45f3-b489-8258473cb62b", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/3448718c-bfd5-427e-95a8-6a73041990c1", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(obj.Position), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(obj.Enabled), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(obj.Locked), true);
            Assert.AreEqual("name-161", TestUtil.ToTestableString(obj.Filename), true);
        }

        [TestMethod]
        public void TestEnableOrDisableBuildpackResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""2e881f77-8f73-4189-9569-e782aa84626e"",
    ""url"": ""/v2/buildpacks/b6180bd4-e282-4d17-b594-a86b1f0fc197"",
    ""created_at"": ""2016-03-30T10:15:08Z"",
    ""updated_at"": ""2016-03-30T10:15:08Z""
  },
  ""entity"": {
    ""name"": ""name_1"",
    ""position"": 1,
    ""enabled"": false,
    ""locked"": false,
    ""filename"": ""name-167""
  }
}";

            EnableOrDisableBuildpackResponse obj = Utilities.DeserializeJson<EnableOrDisableBuildpackResponse>(json);

            Assert.AreEqual("2e881f77-8f73-4189-9569-e782aa84626e", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/buildpacks/b6180bd4-e282-4d17-b594-a86b1f0fc197", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("2016-03-30T10:15:08Z", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name_1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(obj.Position), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.Enabled), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.Locked), true);
            Assert.AreEqual("name-167", TestUtil.ToTestableString(obj.Filename), true);
        }
    }
}
