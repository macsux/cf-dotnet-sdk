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
    public class ServiceUsageEventsTest
    {


        [TestMethod]
        public void TestListServiceUsageEventsResponse()
        {
            string json = @"{
  ""total_results"": 2,
  ""total_pages"": 2,
  ""prev_url"": null,
  ""next_url"": ""/v2/service_usage_events?after_guid=0298da9e-3658-48ca-a4cf-f5f3460be390=asc=2=1"",
  ""resources"": [
    {
      ""metadata"": {
        ""guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""url"": ""/v2/service_usage_events/9f23ea2f-35c8-4d65-a095-220474679ed5"",
        ""created_at"": ""2017-01-04T15:59:00Z""
      },
      ""entity"": {
        ""state"": ""CREATED"",
        ""org_guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""space_guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""space_name"": ""name-2173"",
        ""service_instance_guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""service_instance_name"": ""name-2174"",
        ""service_instance_type"": ""type-8"",
        ""service_plan_guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""service_plan_name"": ""name-2175"",
        ""service_guid"": ""13bde165-d0f6-475b-b922-a0242125d7a6"",
        ""service_label"": ""label-51""
      }
    }
  ]
}";

            PagedResponseCollection<ListServiceUsageEventsResponse> page = Utilities.DeserializePage<ListServiceUsageEventsResponse>(json, null);

            Assert.AreEqual("2", TestUtil.ToTestableString(page.Properties.TotalResults), true);
            Assert.AreEqual("2", TestUtil.ToTestableString(page.Properties.TotalPages), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.PreviousUrl), true);
            Assert.AreEqual("/v2/service_usage_events?after_guid=0298da9e-3658-48ca-a4cf-f5f3460be390=asc=2=1", TestUtil.ToTestableString(page.Properties.NextUrl), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/service_usage_events/9f23ea2f-35c8-4d65-a095-220474679ed5", TestUtil.ToTestableString(page[0].EntityMetadata.Url), true);
            Assert.AreEqual("2017-01-04T15:59:00Z", TestUtil.ToTestableString(page[0].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("CREATED", TestUtil.ToTestableString(page[0].State), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].OrgGuid), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].SpaceGuid), true);
            Assert.AreEqual("name-2173", TestUtil.ToTestableString(page[0].SpaceName), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].ServiceInstanceGuid), true);
            Assert.AreEqual("name-2174", TestUtil.ToTestableString(page[0].ServiceInstanceName), true);
            Assert.AreEqual("type-8", TestUtil.ToTestableString(page[0].ServiceInstanceType), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].ServicePlanGuid), true);
            Assert.AreEqual("name-2175", TestUtil.ToTestableString(page[0].ServicePlanName), true);
            Assert.AreEqual("13bde165-d0f6-475b-b922-a0242125d7a6", TestUtil.ToTestableString(page[0].ServiceGuid), true);
            Assert.AreEqual("label-51", TestUtil.ToTestableString(page[0].ServiceLabel), true);
        }

        [TestMethod]
        public void TestRetrieveServiceUsageEventResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""url"": ""/v2/service_usage_events/5de325a0-7636-49ef-8900-c6e3d9c500a1"",
    ""created_at"": ""2017-01-04T15:59:00Z""
  },
  ""entity"": {
    ""state"": ""CREATED"",
    ""org_guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""space_guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""space_name"": ""name-2161"",
    ""service_instance_guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""service_instance_name"": ""name-2162"",
    ""service_instance_type"": ""type-4"",
    ""service_plan_guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""service_plan_name"": ""name-2163"",
    ""service_guid"": ""a3acbf24-e2b3-428b-8e00-b48c87b5559e"",
    ""service_label"": ""label-47""
  }
}";

            RetrieveServiceUsageEventResponse obj = Utilities.DeserializeJson<RetrieveServiceUsageEventResponse>(json);

            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/service_usage_events/5de325a0-7636-49ef-8900-c6e3d9c500a1", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2017-01-04T15:59:00Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("CREATED", TestUtil.ToTestableString(obj.State), true);
            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.OrgGuid), true);
            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.SpaceGuid), true);
            Assert.AreEqual("name-2161", TestUtil.ToTestableString(obj.SpaceName), true);
            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.ServiceInstanceGuid), true);
            Assert.AreEqual("name-2162", TestUtil.ToTestableString(obj.ServiceInstanceName), true);
            Assert.AreEqual("type-4", TestUtil.ToTestableString(obj.ServiceInstanceType), true);
            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.ServicePlanGuid), true);
            Assert.AreEqual("name-2163", TestUtil.ToTestableString(obj.ServicePlanName), true);
            Assert.AreEqual("a3acbf24-e2b3-428b-8e00-b48c87b5559e", TestUtil.ToTestableString(obj.ServiceGuid), true);
            Assert.AreEqual("label-47", TestUtil.ToTestableString(obj.ServiceLabel), true);
        }
    }
}
