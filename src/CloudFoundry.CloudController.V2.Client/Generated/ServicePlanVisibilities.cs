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

using CloudFoundry.CloudController.Common;
using CloudFoundry.CloudController.V2.Client.Data;
using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Threading.Tasks;


namespace CloudFoundry.CloudController.V2.Client
{
    /// <summary>
    /// ServicePlanVisibilities Endpoint
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public partial class ServicePlanVisibilitiesEndpoint : CloudFoundry.CloudController.V2.Client.Base.AbstractServicePlanVisibilitiesEndpoint
    {
        internal ServicePlanVisibilitiesEndpoint(CloudFoundryClient client) : base()
        {
            this.Client = client;
        }
    }
}

namespace CloudFoundry.CloudController.V2.Client.Base
{
    /// <summary>
    /// Base abstract class for ServicePlanVisibilities Endpoint
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public abstract class AbstractServicePlanVisibilitiesEndpoint : BaseEndpoint
    {
        /// <summary>
        /// Initializes the class
        /// </summary>
        protected AbstractServicePlanVisibilitiesEndpoint()
        {
        }

        /// <summary>
        /// List all Service Plan Visibilities
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/list_all_service_plan_visibilities.html"</para>
        /// </summary>
        public async Task<PagedResponseCollection<ListAllServicePlanVisibilitiesResponse>> ListAllServicePlanVisibilities()
        {
            return await ListAllServicePlanVisibilities(new RequestOptions());
        }

        /// <summary>
        /// List all Service Plan Visibilities
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/list_all_service_plan_visibilities.html"</para>
        /// </summary>
        public async Task<PagedResponseCollection<ListAllServicePlanVisibilitiesResponse>> ListAllServicePlanVisibilities(RequestOptions options)
        {
            UriBuilder uriBuilder = new UriBuilder(this.Client.CloudTarget);
            uriBuilder.Path = "/v2/service_plan_visibilities";
            uriBuilder.Query = options.ToString();
            var client = this.GetHttpClient();
            client.Uri = uriBuilder.Uri;
            client.Method = HttpMethod.Get;
            client.Headers.Add(await BuildAuthenticationHeader());
            var expectedReturnStatus = 200;
            var response = await this.SendAsync(client, expectedReturnStatus);
            return Utilities.DeserializePage<ListAllServicePlanVisibilitiesResponse>(await response.ReadContentAsStringAsync(), this.Client);
        }

        /// <summary>
        /// Creating a Service Plan Visibility
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/creating_a_service_plan_visibility.html"</para>
        /// </summary>
        public async Task<CreateServicePlanVisibilityResponse> CreateServicePlanVisibility(CreateServicePlanVisibilityRequest value)
        {
            UriBuilder uriBuilder = new UriBuilder(this.Client.CloudTarget);
            uriBuilder.Path = "/v2/service_plan_visibilities";
            var client = this.GetHttpClient();
            client.Uri = uriBuilder.Uri;
            client.Method = HttpMethod.Post;
            client.Headers.Add(await BuildAuthenticationHeader());
            client.ContentType = "application/x-www-form-urlencoded";
            client.Content = JsonConvert.SerializeObject(value).ConvertToStream();
            var expectedReturnStatus = 201;
            var response = await this.SendAsync(client, expectedReturnStatus);
            return Utilities.DeserializeJson<CreateServicePlanVisibilityResponse>(await response.ReadContentAsStringAsync());
        }

        /// <summary>
        /// Delete a Particular Service Plan Visibilities
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/delete_a_particular_service_plan_visibilities.html"</para>
        /// </summary>
        public async Task DeleteServicePlanVisibilities(Guid? guid)
        {
            UriBuilder uriBuilder = new UriBuilder(this.Client.CloudTarget);
            uriBuilder.Path = string.Format(CultureInfo.InvariantCulture, "/v2/service_plan_visibilities/{0}", guid);
            var client = this.GetHttpClient();
            client.Uri = uriBuilder.Uri;
            client.Method = HttpMethod.Delete;
            client.Headers.Add(await BuildAuthenticationHeader());
            client.ContentType = "application/x-www-form-urlencoded";
            var expectedReturnStatus = 204;
            var response = await this.SendAsync(client, expectedReturnStatus);
        }

        /// <summary>
        /// Updating a Service Plan Visibility
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/updating_a_service_plan_visibility.html"</para>
        /// </summary>
        public async Task<UpdateServicePlanVisibilityResponse> UpdateServicePlanVisibility(Guid? guid, UpdateServicePlanVisibilityRequest value)
        {
            UriBuilder uriBuilder = new UriBuilder(this.Client.CloudTarget);
            uriBuilder.Path = string.Format(CultureInfo.InvariantCulture, "/v2/service_plan_visibilities/{0}", guid);
            var client = this.GetHttpClient();
            client.Uri = uriBuilder.Uri;
            client.Method = HttpMethod.Put;
            client.Headers.Add(await BuildAuthenticationHeader());
            client.ContentType = "application/x-www-form-urlencoded";
            client.Content = JsonConvert.SerializeObject(value).ConvertToStream();
            var expectedReturnStatus = 201;
            var response = await this.SendAsync(client, expectedReturnStatus);
            return Utilities.DeserializeJson<UpdateServicePlanVisibilityResponse>(await response.ReadContentAsStringAsync());
        }

        /// <summary>
        /// Retrieve a Particular Service Plan Visibility
        /// <para>For detailed information, see online documentation at: "http://apidocs.cloudfoundry.org/195/service_plan_visibilities/retrieve_a_particular_service_plan_visibility.html"</para>
        /// </summary>
        public async Task<RetrieveServicePlanVisibilityResponse> RetrieveServicePlanVisibility(Guid? guid)
        {
            UriBuilder uriBuilder = new UriBuilder(this.Client.CloudTarget);
            uriBuilder.Path = string.Format(CultureInfo.InvariantCulture, "/v2/service_plan_visibilities/{0}", guid);
            var client = this.GetHttpClient();
            client.Uri = uriBuilder.Uri;
            client.Method = HttpMethod.Get;
            client.Headers.Add(await BuildAuthenticationHeader());
            var expectedReturnStatus = 200;
            var response = await this.SendAsync(client, expectedReturnStatus);
            return Utilities.DeserializeJson<RetrieveServicePlanVisibilityResponse>(await response.ReadContentAsStringAsync());
        }
    }
}