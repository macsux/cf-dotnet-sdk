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
    public class RoutesTest
    {

        [TestMethod]
        public void TestUpdateRouteRequest()
        {
            string json = @"{
  ""port"": 10000
}";

            UpdateRouteRequest request = new UpdateRouteRequest();

            request.Port = 10000;
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestCreateRouteRequest()
        {
            string json = @"{
  ""domain_guid"": ""74324be7-c811-4452-8cbd-09a0353a0e13"",
  ""space_guid"": ""74324be7-c811-4452-8cbd-09a0353a0e13"",
  ""port"": 10000
}";

            CreateRouteRequest request = new CreateRouteRequest();

            request.DomainGuid = new Guid("74324be7-c811-4452-8cbd-09a0353a0e13");
            request.SpaceGuid = new Guid("74324be7-c811-4452-8cbd-09a0353a0e13");
            request.Port = 10000;
            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
    }
}
