using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeyHub.Model.Definition.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace KeyHub.Data.Managers
{
    public class KeyHubRoleManager : RoleManager<KeyHubRole>
    {
        public KeyHubRoleManager(IRoleStore<KeyHubRole, string> store)
            : base(store)
        {
        }
    }
}
