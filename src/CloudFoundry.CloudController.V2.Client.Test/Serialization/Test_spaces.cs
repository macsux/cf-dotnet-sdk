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
using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;

namespace CloudFoundry.CloudController.V2.Test.Serialization
{
    [TestClass]
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public class SpacesTest
    {

        [TestMethod]
        public void TestRemoveAuditorWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""auditor@example.com""
}";

            RemoveAuditorWithSpaceByUsernameRequest request = new RemoveAuditorWithSpaceByUsernameRequest();

            request.Username = "auditor@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestAssociateAuditorWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""user@example.com""
}";

            AssociateAuditorWithSpaceByUsernameRequest request = new AssociateAuditorWithSpaceByUsernameRequest();

            request.Username = "user@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestRemoveDeveloperWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""developer@example.com""
}";

            RemoveDeveloperWithSpaceByUsernameRequest request = new RemoveDeveloperWithSpaceByUsernameRequest();

            request.Username = "developer@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestAssociateManagerWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""user@example.com""
}";

            AssociateManagerWithSpaceByUsernameRequest request = new AssociateManagerWithSpaceByUsernameRequest();

            request.Username = "user@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestAssociateDeveloperWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""user@example.com""
}";

            AssociateDeveloperWithSpaceByUsernameRequest request = new AssociateDeveloperWithSpaceByUsernameRequest();

            request.Username = "user@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestCreateSpaceRequest()
        {
            string json = @"{
  ""name"": ""development"",
  ""organization_guid"": ""b625ecba-6cf8-48ca-b70d-170777f10196""
}";

            CreateSpaceRequest request = new CreateSpaceRequest();

            request.Name = "development";
            request.OrganizationGuid = new Guid("b625ecba-6cf8-48ca-b70d-170777f10196");
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestRemoveManagerWithSpaceByUsernameRequest()
        {
            string json = @"{
  ""username"": ""manager@example.com""
}";

            RemoveManagerWithSpaceByUsernameRequest request = new RemoveManagerWithSpaceByUsernameRequest();

            request.Username = "manager@example.com";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestUpdateSpaceRequest()
        {
            string json = @"{
  ""name"": ""New Space Name""
}";

            UpdateSpaceRequest request = new UpdateSpaceRequest();

            request.Name = "New Space Name";
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestSetIsolationSegmentForSpaceExperimentalRequest()
        {
            string json = @"{""isolation_segment_guid"":""4e9dfae7-770a-45d9-8113-2cfc24790af4""}";

            SetIsolationSegmentForSpaceExperimentalRequest request = new SetIsolationSegmentForSpaceExperimentalRequest();

            request.IsolationSegmentGuid = new Guid("4e9dfae7-770a-45d9-8113-2cfc24790af4");
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
    }
}
