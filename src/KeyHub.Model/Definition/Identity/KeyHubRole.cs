using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;

namespace KeyHub.Model.Definition.Identity
{
    public partial class KeyHubRole : IdentityRole
    {
        /// <summary>
        /// Name of the System Administrator role
        /// </summary>
        public const string SystemAdmin = "Sys_Administrator";

        /// <summary>
        /// Name of a regular user role
        /// </summary>
        public const string RegularUser = "User";
    }
}
