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
    public class ServiceBindingsTest
    {

        [TestMethod]
        public void TestCreateServiceBindingRequest()
        {
            string json = @"{
  ""service_instance_guid"": ""c1aeb11b-8f02-4eb7-88d8-fc62959fe80e"",
  ""app_guid"": ""c1aeb11b-8f02-4eb7-88d8-fc62959fe80e"",
  ""parameters"": {
    ""the_service_broker"": ""wants this object""
  }
}";

            CreateServiceBindingRequest request = new CreateServiceBindingRequest();

            request.ServiceInstanceGuid = new Guid("c1aeb11b-8f02-4eb7-88d8-fc62959fe80e");
            request.AppGuid = new Guid("c1aeb11b-8f02-4eb7-88d8-fc62959fe80e");
            request.Parameters = TestUtil.GetJsonDictonary(@"{""the_service_broker"":""wants this object""}");

            string result = JsonConvert.SerializeObject(request, Formatting.None);
            Assert.AreEqual(TestUtil.ToUnformatedJsonString(json), result);
        }
    }
}
