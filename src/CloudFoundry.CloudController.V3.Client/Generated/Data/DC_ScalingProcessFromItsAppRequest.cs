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
    /// Data class used for serializing the "CloudFoundry.CloudController.V3.Client.AppsEndpoint.ScalingProcessFromItsApp()" Request
    /// <para>For usage information, see online documentation at "http://apidocs.cloudfoundry.org/195/apps__experimental_/scaling_a_process_from_its_app.html"</para>
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public partial class ScalingProcessFromItsAppRequest : CloudFoundry.CloudController.V3.Client.Data.Base.AbstractScalingProcessFromItsAppRequest
    {
    }
}

namespace CloudFoundry.CloudController.V3.Client.Data.Base
{
    /// <summary>
    /// Base abstract data class used for serializing the "CloudFoundry.CloudController.V3.Client.AppsEndpoint.ScalingProcessFromItsApp()" Request
    /// <para>For usage information, see online documentation at "http://apidocs.cloudfoundry.org/195/apps__experimental_/scaling_a_process_from_its_app.html"</para>
    /// </summary>
    [GeneratedCodeAttribute("cf-sdk-builder", "1.0.0.0")]
    public abstract class AbstractScalingProcessFromItsAppRequest
    {

        /// <summary> 
        /// <para>The Instances</para>
        /// </summary>
        [JsonProperty("instances", NullValueHandling = NullValueHandling.Ignore)]
        public int? Instances
        {
            get;
            set;
        }
    }
}