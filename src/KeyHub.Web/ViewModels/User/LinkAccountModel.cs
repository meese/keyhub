using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;
using KeyHub.Data;
using Microsoft.Owin.Security;

namespace KeyHub.Web.ViewModels.User
{
    public class LinkAccountModel
    {
        public IEnumerable<string> OpenIDProvidersAvailable;
        public IEnumerable<string> OpenIDProvidersLinked;
        public bool AllowRemovingLogin;

        public static LinkAccountModel ForUser(IDataContext context, IIdentity identity)
        {
            var user = context.GetUser(identity);
            var allProviders =
                HttpContext.Current.GetOwinContext()
                    .Authentication.GetExternalAuthenticationTypes()
                    .Select(c => c.Caption)
                    .ToArray();

            //  Match each linked provider to the member of allProviders as allProviders has proper casing (Google, not google)
            var identityUser = context.CreateUserManager().Users.First(u => u.Id == user.MembershipUserIdentifier);
            var linkedProviders = identityUser.Logins.Select(lp => allProviders.Single(ap => ap.ToLower() == lp.LoginProvider.ToLower()))
                .ToArray();

            var loginMethodCount = linkedProviders.Count() + 1;

            var model = new LinkAccountModel()
            {
                OpenIDProvidersLinked = linkedProviders,
                OpenIDProvidersAvailable = allProviders.Where(p => !linkedProviders.Contains(p)),
                AllowRemovingLogin = loginMethodCount > 1
            };

            return model;
        }
    }
}