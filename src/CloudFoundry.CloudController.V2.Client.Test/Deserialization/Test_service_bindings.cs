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
    public class ServiceBindingsTest
    {


        [TestMethod]
        public void TestListAllServiceBindingsResponse()
        {
            string json = @"{
  ""total_results"": 1,
  ""total_pages"": 1,
  ""prev_url"": null,
  ""next_url"": null,
  ""resources"": [
    {
      ""metadata"": {
        ""guid"": ""a4ad73e3-4101-499f-ba01-ee1032d8e6f9"",
        ""url"": ""/v2/service_bindings/c95e6b26-d74c-4a0f-83f0-ae023d4f745c"",
        ""created_at"": ""2016-03-30T10:15:46Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""app_guid"": ""a4ad73e3-4101-499f-ba01-ee1032d8e6f9"",
        ""service_instance_guid"": ""a4ad73e3-4101-499f-ba01-ee1032d8e6f9"",
        ""credentials"": {
          ""creds-key-67"": ""creds-val-67""
        },
        ""binding_options"": {

        },
        ""gateway_data"": null,
        ""gateway_name"": """",
        ""syslog_drain_url"": null,
        ""app_url"": ""/v2/apps/bb1d386a-f3b7-449c-8ded-912c66c4e7a3"",
        ""service_instance_url"": ""/v2/service_instances/b9a18d42-9647-4b66-a3c9-e0a7d40b05bd""
      }
    }
  ]
}";

            PagedResponseCollection<ListAllServiceBindingsResponse> page = Utilities.DeserializePage<ListAllServiceBindingsResponse>(json, null);

            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalResults), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalPages), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.PreviousUrl), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.NextUrl), true);
            Assert.AreEqual("a4ad73e3-4101-499f-ba01-ee1032d8e6f9", TestUtil.ToTestableString(page[0].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/service_bindings/c95e6b26-d74c-4a0f-83f0-ae023d4f745c", TestUtil.ToTestableString(page[0].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:46Z", TestUtil.ToTestableString(page[0].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("a4ad73e3-4101-499f-ba01-ee1032d8e6f9", TestUtil.ToTestableString(page[0].AppGuid), true);
            Assert.AreEqual("a4ad73e3-4101-499f-ba01-ee1032d8e6f9", TestUtil.ToTestableString(page[0].ServiceInstanceGuid), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].GatewayData), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].GatewayName), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].SyslogDrainUrl), true);
            Assert.AreEqual("/v2/apps/bb1d386a-f3b7-449c-8ded-912c66c4e7a3", TestUtil.ToTestableString(page[0].AppUrl), true);
            Assert.AreEqual("/v2/service_instances/b9a18d42-9647-4b66-a3c9-e0a7d40b05bd", TestUtil.ToTestableString(page[0].ServiceInstanceUrl), true);
        }

        [TestMethod]
        public void TestRetrieveServiceBindingResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""3809dc66-b934-48e6-b62e-bd1a2af1ef58"",
    ""url"": ""/v2/service_bindings/0347d612-7dbf-4260-9a53-8941775e8d5e"",
    ""created_at"": ""2016-03-30T10:15:47Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""app_guid"": ""3809dc66-b934-48e6-b62e-bd1a2af1ef58"",
    ""service_instance_guid"": ""3809dc66-b934-48e6-b62e-bd1a2af1ef58"",
    ""credentials"": {
      ""creds-key-72"": ""creds-val-72""
    },
    ""binding_options"": {

    },
    ""gateway_data"": null,
    ""gateway_name"": """",
    ""syslog_drain_url"": null,
    ""app_url"": ""/v2/apps/2473e12a-05bc-4956-a576-663970a43669"",
    ""service_instance_url"": ""/v2/service_instances/f1ab15a9-5fd8-44c4-8524-b9ac13246ee4""
  }
}";

            RetrieveServiceBindingResponse obj = Utilities.DeserializeJson<RetrieveServiceBindingResponse>(json);

            Assert.AreEqual("3809dc66-b934-48e6-b62e-bd1a2af1ef58", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/service_bindings/0347d612-7dbf-4260-9a53-8941775e8d5e", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:47Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("3809dc66-b934-48e6-b62e-bd1a2af1ef58", TestUtil.ToTestableString(obj.AppGuid), true);
            Assert.AreEqual("3809dc66-b934-48e6-b62e-bd1a2af1ef58", TestUtil.ToTestableString(obj.ServiceInstanceGuid), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.GatewayData), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.GatewayName), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.SyslogDrainUrl), true);
            Assert.AreEqual("/v2/apps/2473e12a-05bc-4956-a576-663970a43669", TestUtil.ToTestableString(obj.AppUrl), true);
            Assert.AreEqual("/v2/service_instances/f1ab15a9-5fd8-44c4-8524-b9ac13246ee4", TestUtil.ToTestableString(obj.ServiceInstanceUrl), true);
        }

        [TestMethod]
        public void TestCreateServiceBindingResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""94e8b60d-7d2a-4c39-9278-f707fadf7cae"",
    ""url"": ""/v2/service_bindings/99b1b426-73bf-4316-8ee7-fc1f499a5fa4"",
    ""created_at"": ""2016-03-30T10:15:47Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""app_guid"": ""94e8b60d-7d2a-4c39-9278-f707fadf7cae"",
    ""service_instance_guid"": ""94e8b60d-7d2a-4c39-9278-f707fadf7cae"",
    ""credentials"": {
      ""creds-key-71"": ""creds-val-71""
    },
    ""binding_options"": {

    },
    ""gateway_data"": null,
    ""gateway_name"": """",
    ""syslog_drain_url"": null,
    ""app_url"": ""/v2/apps/c69c928b-4092-43d1-889f-f3e409b9d48a"",
    ""service_instance_url"": ""/v2/user_provided_service_instances/3fcc04bf-6f0e-4ebf-bc9d-7a89872c6188""
  }
}";

            CreateServiceBindingResponse obj = Utilities.DeserializeJson<CreateServiceBindingResponse>(json);

            Assert.AreEqual("94e8b60d-7d2a-4c39-9278-f707fadf7cae", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/service_bindings/99b1b426-73bf-4316-8ee7-fc1f499a5fa4", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:47Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("94e8b60d-7d2a-4c39-9278-f707fadf7cae", TestUtil.ToTestableString(obj.AppGuid), true);
            Assert.AreEqual("94e8b60d-7d2a-4c39-9278-f707fadf7cae", TestUtil.ToTestableString(obj.ServiceInstanceGuid), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.GatewayData), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.GatewayName), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.SyslogDrainUrl), true);
            Assert.AreEqual("/v2/apps/c69c928b-4092-43d1-889f-f3e409b9d48a", TestUtil.ToTestableString(obj.AppUrl), true);
            Assert.AreEqual("/v2/user_provided_service_instances/3fcc04bf-6f0e-4ebf-bc9d-7a89872c6188", TestUtil.ToTestableString(obj.ServiceInstanceUrl), true);
        }
    }
}
