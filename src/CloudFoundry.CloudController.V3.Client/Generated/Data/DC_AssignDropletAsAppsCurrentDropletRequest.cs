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

using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;

namespace CloudFoundry.CloudController.V3.Client.Data
{
    /// <summary>
    /// Data class used for serializing the "CloudFoundry.CloudController.V3.Client.AppsEndpoint.AssignDropletAsAppsCurrentDroplet()" Request
    /// <para>For usage information, see online documentation at "http://apidocs.cloudfoundry.org/195/apps__experimental_/assigning_a_droplet_as_a_an_apps_current_droplet.html"</para>
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public partial class AssignDropletAsAppsCurrentDropletRequest : CloudFoundry.CloudController.V3.Client.Data.Base.AbstractAssignDropletAsAppsCurrentDropletRequest
    {
    }
}

namespace CloudFoundry.CloudController.V3.Client.Data.Base
{
    /// <summary>
    /// Base abstract data class used for serializing the "CloudFoundry.CloudController.V3.Client.AppsEndpoint.AssignDropletAsAppsCurrentDroplet()" Request
    /// <para>For usage information, see online documentation at "http://apidocs.cloudfoundry.org/195/apps__experimental_/assigning_a_droplet_as_a_an_apps_current_droplet.html"</para>
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public abstract class AbstractAssignDropletAsAppsCurrentDropletRequest
    {

        /// <summary> 
        /// <para>The Desired Droplet Guid</para>
        /// </summary>
        [JsonProperty("desired_droplet_guid", NullValueHandling = NullValueHandling.Ignore)]
        public string DesiredDropletGuid
        {
            get;
            set;
        }
    }
}