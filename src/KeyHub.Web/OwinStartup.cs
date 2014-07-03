﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using Castle.Core.Internal;
using KeyHub.Data;
using KeyHub.Model.Definition.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;

namespace KeyHub.Web
{
    public class OwinStartup
    {
        //owin is required for parts of asp.identity esp authentication which is what we are using it for here
        //you could remove owin but you would have to use old forms auth instead
        //should probabley not use it besides for owncontext.auth so we don't introduce another middlelayer to this project
        public void Configuration(IAppBuilder app)
        {

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<KeyHubUserManager, KeyHubUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);


            //external login services
            var microsoftClientId = WebConfigurationManager.AppSettings["microsoftClientId"];
            var microsoftClientSecret = WebConfigurationManager.AppSettings["microsoftClientSecret"];
            if (!microsoftClientSecret.IsNullOrEmpty() && !microsoftClientId.IsNullOrEmpty())
                app.UseMicrosoftAccountAuthentication(
                    clientId: microsoftClientId,
                    clientSecret: "");

            var twitterConsumerKey = WebConfigurationManager.AppSettings["twitterConsumerKey"];
            var twitterConsumerSecret = WebConfigurationManager.AppSettings["twitterConsumerSecret"];
            if (!twitterConsumerKey.IsNullOrEmpty() && !twitterConsumerSecret.IsNullOrEmpty())
                app.UseTwitterAuthentication(
                   consumerKey: twitterConsumerKey,
                   consumerSecret: twitterConsumerSecret);

            var facebookAppId = WebConfigurationManager.AppSettings["facebookAppId"];
            var facebookAppSecret = WebConfigurationManager.AppSettings["facebookAppSecret"];
            if (!facebookAppId.IsNullOrEmpty() && !facebookAppSecret.IsNullOrEmpty())
                app.UseFacebookAuthentication(
                   appId: facebookAppId,
                   appSecret: facebookAppSecret);

            app.UseGoogleAuthentication();

        }


    }


    public class KeyHubSignInManager : SignInManager<KeyHubUser, string>
    {
        public KeyHubSignInManager(UserManager<KeyHubUser, string> userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }
    }
}