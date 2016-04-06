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
    public class SecurityGroupsTest
    {


        [TestMethod]
        public void TestUpdateSecurityGroupResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""f38f3e1e-35a4-4597-97e4-e913667b1e18"",
    ""url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122"",
    ""created_at"": ""2016-03-30T10:15:02Z"",
    ""updated_at"": ""2016-03-30T10:15:24Z""
  },
  ""entity"": {
    ""name"": ""new_name"",
    ""rules"": [

    ],
    ""running_default"": false,
    ""staging_default"": false,
    ""spaces_url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces""
  }
}";

            UpdateSecurityGroupResponse obj = Utilities.DeserializeJson<UpdateSecurityGroupResponse>(json);

            Assert.AreEqual("f38f3e1e-35a4-4597-97e4-e913667b1e18", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:02Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("new_name", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces", TestUtil.ToTestableString(obj.SpacesUrl), true);
        }

        [TestMethod]
        public void TestListAllSecurityGroupsResponse()
        {
            string json = @"{
  ""total_results"": 5,
  ""total_pages"": 1,
  ""prev_url"": null,
  ""next_url"": null,
  ""resources"": [
    {
      ""metadata"": {
        ""guid"": ""c15b4e36-618a-489a-9edf-88b8d4213fed"",
        ""url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122"",
        ""created_at"": ""2016-03-30T10:15:02Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""dummy1"",
        ""rules"": [

        ],
        ""running_default"": false,
        ""staging_default"": false,
        ""spaces_url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""c15b4e36-618a-489a-9edf-88b8d4213fed"",
        ""url"": ""/v2/security_groups/dd397a6f-f39f-45e1-b439-f21e2dd9355a"",
        ""created_at"": ""2016-03-30T10:15:02Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""dummy2"",
        ""rules"": [

        ],
        ""running_default"": false,
        ""staging_default"": false,
        ""spaces_url"": ""/v2/security_groups/dd397a6f-f39f-45e1-b439-f21e2dd9355a/spaces""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""c15b4e36-618a-489a-9edf-88b8d4213fed"",
        ""url"": ""/v2/security_groups/1c7d3ce5-285f-4c55-b59e-148577364ddf"",
        ""created_at"": ""2016-03-30T10:15:24Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name-1678"",
        ""rules"": [
          {
            ""protocol"": ""udp"",
            ""ports"": ""8080"",
            ""destination"": ""198.41.191.47/1""
          }
        ],
        ""running_default"": false,
        ""staging_default"": false,
        ""spaces_url"": ""/v2/security_groups/1c7d3ce5-285f-4c55-b59e-148577364ddf/spaces""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""c15b4e36-618a-489a-9edf-88b8d4213fed"",
        ""url"": ""/v2/security_groups/98ab88f1-e71e-4083-a48e-8f7ef7b75355"",
        ""created_at"": ""2016-03-30T10:15:24Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name-1679"",
        ""rules"": [
          {
            ""protocol"": ""udp"",
            ""ports"": ""8080"",
            ""destination"": ""198.41.191.47/1""
          }
        ],
        ""running_default"": false,
        ""staging_default"": false,
        ""spaces_url"": ""/v2/security_groups/98ab88f1-e71e-4083-a48e-8f7ef7b75355/spaces""
      }
    },
    {
      ""metadata"": {
        ""guid"": ""c15b4e36-618a-489a-9edf-88b8d4213fed"",
        ""url"": ""/v2/security_groups/15f2f3f0-4947-42ee-9b72-085eb87a66e6"",
        ""created_at"": ""2016-03-30T10:15:24Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name-1680"",
        ""rules"": [
          {
            ""protocol"": ""udp"",
            ""ports"": ""8080"",
            ""destination"": ""198.41.191.47/1""
          }
        ],
        ""running_default"": false,
        ""staging_default"": false,
        ""spaces_url"": ""/v2/security_groups/15f2f3f0-4947-42ee-9b72-085eb87a66e6/spaces""
      }
    }
  ]
}";

            PagedResponseCollection<ListAllSecurityGroupsResponse> page = Utilities.DeserializePage<ListAllSecurityGroupsResponse>(json, null);

            Assert.AreEqual("5", TestUtil.ToTestableString(page.Properties.TotalResults), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalPages), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.PreviousUrl), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.NextUrl), true);
            Assert.AreEqual("c15b4e36-618a-489a-9edf-88b8d4213fed", TestUtil.ToTestableString(page[0].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122", TestUtil.ToTestableString(page[0].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:02Z", TestUtil.ToTestableString(page[0].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("dummy1", TestUtil.ToTestableString(page[0].Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[0].RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[0].StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces", TestUtil.ToTestableString(page[0].SpacesUrl), true);
            Assert.AreEqual("c15b4e36-618a-489a-9edf-88b8d4213fed", TestUtil.ToTestableString(page[1].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/dd397a6f-f39f-45e1-b439-f21e2dd9355a", TestUtil.ToTestableString(page[1].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:02Z", TestUtil.ToTestableString(page[1].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[1].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("dummy2", TestUtil.ToTestableString(page[1].Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[1].RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[1].StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/dd397a6f-f39f-45e1-b439-f21e2dd9355a/spaces", TestUtil.ToTestableString(page[1].SpacesUrl), true);
            Assert.AreEqual("c15b4e36-618a-489a-9edf-88b8d4213fed", TestUtil.ToTestableString(page[2].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/1c7d3ce5-285f-4c55-b59e-148577364ddf", TestUtil.ToTestableString(page[2].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(page[2].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[2].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name-1678", TestUtil.ToTestableString(page[2].Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[2].RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[2].StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/1c7d3ce5-285f-4c55-b59e-148577364ddf/spaces", TestUtil.ToTestableString(page[2].SpacesUrl), true);
            Assert.AreEqual("c15b4e36-618a-489a-9edf-88b8d4213fed", TestUtil.ToTestableString(page[3].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/98ab88f1-e71e-4083-a48e-8f7ef7b75355", TestUtil.ToTestableString(page[3].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(page[3].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[3].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name-1679", TestUtil.ToTestableString(page[3].Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[3].RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[3].StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/98ab88f1-e71e-4083-a48e-8f7ef7b75355/spaces", TestUtil.ToTestableString(page[3].SpacesUrl), true);
            Assert.AreEqual("c15b4e36-618a-489a-9edf-88b8d4213fed", TestUtil.ToTestableString(page[4].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/15f2f3f0-4947-42ee-9b72-085eb87a66e6", TestUtil.ToTestableString(page[4].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(page[4].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[4].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name-1680", TestUtil.ToTestableString(page[4].Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[4].RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(page[4].StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/15f2f3f0-4947-42ee-9b72-085eb87a66e6/spaces", TestUtil.ToTestableString(page[4].SpacesUrl), true);
        }

        [TestMethod]
        public void TestRetrieveSecurityGroupResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""635e3254-cb2a-4115-98ae-3649f3b5e54d"",
    ""url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122"",
    ""created_at"": ""2016-03-30T10:15:02Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""name"": ""dummy1"",
    ""rules"": [

    ],
    ""running_default"": false,
    ""staging_default"": false,
    ""spaces_url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces""
  }
}";

            RetrieveSecurityGroupResponse obj = Utilities.DeserializeJson<RetrieveSecurityGroupResponse>(json);

            Assert.AreEqual("635e3254-cb2a-4115-98ae-3649f3b5e54d", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:02Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("dummy1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces", TestUtil.ToTestableString(obj.SpacesUrl), true);
        }

        [TestMethod]
        public void TestListAllSpacesForSecurityGroupResponse()
        {
            string json = @"{
  ""total_results"": 1,
  ""total_pages"": 1,
  ""prev_url"": null,
  ""next_url"": null,
  ""resources"": [
    {
      ""metadata"": {
        ""guid"": ""94ccd10f-1d26-409d-a8a1-4ba90a18fd56"",
        ""url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b"",
        ""created_at"": ""2016-03-30T10:15:24Z"",
        ""updated_at"": null
      },
      ""entity"": {
        ""name"": ""name-1699"",
        ""organization_guid"": ""94ccd10f-1d26-409d-a8a1-4ba90a18fd56"",
        ""space_quota_definition_guid"": null,
        ""allow_ssh"": true,
        ""organization_url"": ""/v2/organizations/bbeeb765-e90f-433d-90af-6b23ebefee79"",
        ""developers_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/developers"",
        ""managers_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/managers"",
        ""auditors_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/auditors"",
        ""apps_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/apps"",
        ""routes_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/routes"",
        ""domains_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/domains"",
        ""service_instances_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/service_instances"",
        ""app_events_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/app_events"",
        ""events_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/events"",
        ""security_groups_url"": ""/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/security_groups""
      }
    }
  ]
}";

            PagedResponseCollection<ListAllSpacesForSecurityGroupResponse> page = Utilities.DeserializePage<ListAllSpacesForSecurityGroupResponse>(json, null);

            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalResults), true);
            Assert.AreEqual("1", TestUtil.ToTestableString(page.Properties.TotalPages), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.PreviousUrl), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page.Properties.NextUrl), true);
            Assert.AreEqual("94ccd10f-1d26-409d-a8a1-4ba90a18fd56", TestUtil.ToTestableString(page[0].EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b", TestUtil.ToTestableString(page[0].EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(page[0].EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("name-1699", TestUtil.ToTestableString(page[0].Name), true);
            Assert.AreEqual("94ccd10f-1d26-409d-a8a1-4ba90a18fd56", TestUtil.ToTestableString(page[0].OrganizationGuid), true);
            Assert.AreEqual("", TestUtil.ToTestableString(page[0].SpaceQuotaDefinitionGuid), true);
            Assert.AreEqual("true", TestUtil.ToTestableString(page[0].AllowSsh), true);
            Assert.AreEqual("/v2/organizations/bbeeb765-e90f-433d-90af-6b23ebefee79", TestUtil.ToTestableString(page[0].OrganizationUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/developers", TestUtil.ToTestableString(page[0].DevelopersUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/managers", TestUtil.ToTestableString(page[0].ManagersUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/auditors", TestUtil.ToTestableString(page[0].AuditorsUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/apps", TestUtil.ToTestableString(page[0].AppsUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/routes", TestUtil.ToTestableString(page[0].RoutesUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/domains", TestUtil.ToTestableString(page[0].DomainsUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/service_instances", TestUtil.ToTestableString(page[0].ServiceInstancesUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/app_events", TestUtil.ToTestableString(page[0].AppEventsUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/events", TestUtil.ToTestableString(page[0].EventsUrl), true);
            Assert.AreEqual("/v2/spaces/37a14dc3-00b6-4440-af64-a7c25f1d1e6b/security_groups", TestUtil.ToTestableString(page[0].SecurityGroupsUrl), true);
        }

        [TestMethod]
        public void TestCreateSecurityGroupResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""805fbaca-6147-438f-8240-1aaf43e118c6"",
    ""url"": ""/v2/security_groups/4c17e35e-bca1-42b1-ae9b-4569dab85e8c"",
    ""created_at"": ""2016-03-30T10:15:24Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""name"": ""my_super_sec_group"",
    ""rules"": [
      {
        ""protocol"": ""icmp"",
        ""destination"": ""0.0.0.0/0"",
        ""type"": 0,
        ""code"": 1
      },
      {
        ""protocol"": ""tcp"",
        ""destination"": ""0.0.0.0/0"",
        ""ports"": ""2048-3000"",
        ""log"": true
      },
      {
        ""protocol"": ""udp"",
        ""destination"": ""0.0.0.0/0"",
        ""ports"": ""53, 5353""
      },
      {
        ""protocol"": ""all"",
        ""destination"": ""0.0.0.0/0""
      }
    ],
    ""running_default"": false,
    ""staging_default"": false,
    ""spaces_url"": ""/v2/security_groups/4c17e35e-bca1-42b1-ae9b-4569dab85e8c/spaces""
  }
}";

            CreateSecurityGroupResponse obj = Utilities.DeserializeJson<CreateSecurityGroupResponse>(json);

            Assert.AreEqual("805fbaca-6147-438f-8240-1aaf43e118c6", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/4c17e35e-bca1-42b1-ae9b-4569dab85e8c", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:24Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("my_super_sec_group", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/4c17e35e-bca1-42b1-ae9b-4569dab85e8c/spaces", TestUtil.ToTestableString(obj.SpacesUrl), true);
        }

        [TestMethod]
        public void TestAssociateSpaceWithSecurityGroupResponse()
        {
            string json = @"{
  ""metadata"": {
    ""guid"": ""ad7854b0-a78a-42e1-9398-3922d6e1675e"",
    ""url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122"",
    ""created_at"": ""2016-03-30T10:15:02Z"",
    ""updated_at"": null
  },
  ""entity"": {
    ""name"": ""dummy1"",
    ""rules"": [

    ],
    ""running_default"": false,
    ""staging_default"": false,
    ""spaces_url"": ""/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces""
  }
}";

            AssociateSpaceWithSecurityGroupResponse obj = Utilities.DeserializeJson<AssociateSpaceWithSecurityGroupResponse>(json);

            Assert.AreEqual("ad7854b0-a78a-42e1-9398-3922d6e1675e", TestUtil.ToTestableString(obj.EntityMetadata.Guid), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122", TestUtil.ToTestableString(obj.EntityMetadata.Url), true);
            Assert.AreEqual("2016-03-30T10:15:02Z", TestUtil.ToTestableString(obj.EntityMetadata.CreatedAt), true);
            Assert.AreEqual("", TestUtil.ToTestableString(obj.EntityMetadata.UpdatedAt), true);
            Assert.AreEqual("dummy1", TestUtil.ToTestableString(obj.Name), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.RunningDefault), true);
            Assert.AreEqual("false", TestUtil.ToTestableString(obj.StagingDefault), true);
            Assert.AreEqual("/v2/security_groups/84c55705-4cc7-4e10-bf33-7c818c63e122/spaces", TestUtil.ToTestableString(obj.SpacesUrl), true);
        }
    }
}
