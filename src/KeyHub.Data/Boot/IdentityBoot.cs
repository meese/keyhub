using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Web.Security;
using KeyHub.Core.Errors;
using KeyHub.Core.Kernel;
using KeyHub.Model;
using KeyHub.Model.Definition.Identity;
using Microsoft.AspNet.Identity;
using WebMatrix.WebData;

namespace KeyHub.Data.Boot
{
    /// <summary>
    /// Holds the boot procedure for the Membership provider.
    /// This boot procedure must run after the RolesBoot class.
    /// </summary>
    public class IdentitypBoot : IKernelEvent
    {
        private List<IError> issueList = new List<IError>();

        public KernelEventCompletedArguments Execute()
        {
            using (var context = new DataContext())
            {
                var roleManager = context.CreateRoleManager();

               // Create normal user role if not present
                if (!roleManager.RoleExists(KeyHubRole.RegularUser))
                    roleManager.Create(new KeyHubRole { Name = KeyHubRole.RegularUser });

                // Create administator Role if not already present
                if (!roleManager.RoleExists(KeyHubRole.SystemAdmin))
                    roleManager.Create(new KeyHubRole { Name = KeyHubRole.SystemAdmin });

                // Create an administator of not already present     
                var userManager = context.CreateUserManager();
                var identifier = Guid.NewGuid().ToString();

                if (!userManager.Users.Any(u => u.UserName == "admin"))
                {
                    userManager.CreateUser(identifier,"admin@example.net", "admin", "password");
                    userManager.AddToRole(identifier, KeyHubRole.SystemAdmin);
                }
                else
                    identifier = userManager.FindByName("admin").Id;

                //add to addmin role if not already
                if (!userManager.IsInRole(identifier, KeyHubRole.SystemAdmin))
                    userManager.AddToRole(identifier, KeyHubRole.SystemAdmin);
                context.SaveChanges();
            }

            return new KernelEventCompletedArguments { AllowContinue = (!issueList.Any()), KernelEventSucceeded = (!issueList.Any()), Issues = issueList.ToArray() };
        }

        public string DisplayName
        {
            get { return "Asp Identity boot"; }
        }

        public KernelEventsTypes EventType
        {
            get { return KernelEventsTypes.Startup; }
        }

        public int Priority
        {
            get { return 102; }
        }
    }
}