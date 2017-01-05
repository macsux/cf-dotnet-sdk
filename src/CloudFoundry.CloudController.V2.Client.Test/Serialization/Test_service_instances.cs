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
    public class ServiceInstancesTest
    {

        [TestMethod]
        public void TestUpdateServiceInstanceRequest()
        {
            string json = @"{""service_plan_guid"":""92869189-312b-409f-8ba8-e6d9afb20231"",""parameters"":{""the_service_broker"":""wants this object""}}";

            UpdateServiceInstanceRequest request = new UpdateServiceInstanceRequest();

            request.ServicePlanGuid = new Guid("92869189-312b-409f-8ba8-e6d9afb20231");
            request.Parameters = TestUtil.GetJsonDictonary(@"{""the_service_broker"":""wants this object""}");

            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestCreateServiceInstanceRequest()
        {
            string json = @"{
  ""space_guid"": ""5b7cb0e3-9808-42df-9fbd-2091428207f0"",
  ""name"": ""my-service-instance"",
  ""service_plan_guid"": ""5b7cb0e3-9808-42df-9fbd-2091428207f0"",
  ""parameters"": {
    ""the_service_broker"": ""wants this object""
  },
  ""tags"": [
    ""accounting"",
    ""mongodb""
  ]
}";

            CreateServiceInstanceRequest request = new CreateServiceInstanceRequest();

            request.SpaceGuid = new Guid("5b7cb0e3-9808-42df-9fbd-2091428207f0");
            request.Name = "my-service-instance";
            request.ServicePlanGuid = new Guid("5b7cb0e3-9808-42df-9fbd-2091428207f0");
            request.Parameters = TestUtil.GetJsonDictonary(@"{""the_service_broker"":""wants this object""}");

            request.Tags = Array.ConvertAll(TestUtil.GetJsonArray(@"[""accounting"",""mongodb""]"), (p => p.ToString()));

            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
        [TestMethod]
        public void TestBindingServiceInstanceToRouteRequest()
        {
            string json = @"{
  ""parameters"": {
    ""the_service_broker"": ""wants this object""
  }
}";

            BindingServiceInstanceToRouteRequest request = new BindingServiceInstanceToRouteRequest();

            request.Parameters = TestUtil.GetJsonDictonary(@"{""the_service_broker"":""wants this object""}");

            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
    }
}
