using System.Data.Entity;
using System.Security.Claims;
using KeyHub.Model;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity.EntityFramework;

using KeyHub.Model.Definition.Identity;

namespace KeyHub.Data
{
// Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.

    public class KeyHubUserManager : UserManager<KeyHubUser>
    {
        public KeyHubUserManager(IUserStore<KeyHubUser> store)
            : base(store)
        {
            this.UserValidator = new UserValidator<KeyHubUser>(this)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            this.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };
        }

        public IdentityResult CreateUser(String identifier,String email, String name, String password)
        {
            var keyHubUser = new KeyHubUser
            {
                Id = identifier,
                UserName = name,
                Email = email
            };

            var user = new User
            {
                MembershipUserIdentifier = identifier,
                AspIdentityUserIdentifier = identifier,
                Email = name
            };

            keyHubUser.User = user;
            return this.Create(keyHubUser, password);
        }

        public IdentityResult CreateUser(KeyHubUser user, String password)
        {
            return this.Create(user, password);
        }
    }

    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your sms service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // This is useful if you do not want to tear down the database each time you run the application.
    // public class ApplicationDbInitializer : DropCreateDatabaseAlways<DataContext>
    // This example shows you how to create a new database if the Model changes
    public class ApplicationDbInitializer : DropCreateDatabaseIfModelChanges<DataContext> 
    {
        protected override void Seed(DataContext context) {
          //  InitializeIdentityForEF(context);
            base.Seed(context);
        }

        //Create User=Admin@Admin.com with password=Admin@123456 in the Admin role        
       /* public static void InitializeIdentityForEF(DataContext db) {
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<KeyHubUserManager>();
            var roleManager = HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();
            const string name = "admin@example.com";
            const string password = "Admin@123456";
            const string roleName = "Admin";

            //Create Role Admin if it does not exist
            var role = roleManager.FindByName(roleName);
            if (role == null) {
                role = new IdentityRole(roleName);
                var roleresult = roleManager.Create(role);
            }

            var user = userManager.FindByName(name);
            if (user == null) {
                user = new KeyHubUser { UserName = name, Email = name };
                var result = userManager.Create(user, password);
                result = userManager.SetLockoutEnabled(user.Id, false);
            }

            // Add user admin to Role Admin if not already added
            var rolesForUser = userManager.GetRoles(user.Id);
            if (!rolesForUser.Contains(role.Name)) {
                var result = userManager.AddToRole(user.Id, role.Name);
            }
        }*/
    }

  /*  public class KeyHubSignInManager : SignInManager<KeyHubUser, string>
    {
        public KeyHubSignInManager(KeyHubUserManager userManager, IAuthenticationManager authenticationManager) : 
            base(userManager, authenticationManager) { }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(KeyHubUser user)
        {
            return user.GenerateUserIdentityAsync((KeyHubUserManager)UserManager);
        }

        public static KeyHubSignInManager Create(IdentityFactoryOptions<KeyHubSignInManager> options, IOwinContext context)
        {
            return new KeyHubSignInManager(context.GetUserManager<KeyHubUserManager>(), context.Authentication);
        }
    }*/
}
