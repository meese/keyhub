using System.Data.Entity;
using System.Security.Claims;
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

    public class KeyHubUserManager : UserManager<KeyHubUser>, IKeyHubUserManager
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

        public IdentityResult CreateUser(KeyHubUser user,String password)
        {
            return this.Create(user, password);
        }
        /* public static KeyHubUserManager Create(IdentityFactoryOptions<KeyHubUserManager> options,
             DataContext context)
         {
             var manager = new KeyHubUserManager(new UserStore<KeyHubUser>(context));
             // Configure validation logic for usernames
             manager.UserValidator = new UserValidator<KeyHubUser>(manager)
             {
                 AllowOnlyAlphanumericUserNames = false,
                 RequireUniqueEmail = true
             };
             // Configure validation logic for passwords
             manager.PasswordValidator = new PasswordValidator
             {
                 RequiredLength = 6,
                 RequireNonLetterOrDigit = true,
                 RequireDigit = true,
                 RequireLowercase = true,
                 RequireUppercase = true,
             };
             // Configure user lockout defaults
             manager.UserLockoutEnabledByDefault = true;
             manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
             manager.MaxFailedAccessAttemptsBeforeLockout = 5;
             // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
             // You can write your own provider and plug in here.
             manager.RegisterTwoFactorProvider("PhoneCode", new PhoneNumberTokenProvider<KeyHubUser>
             {
                 MessageFormat = "Your security code is: {0}"
             });
             manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<KeyHubUser>
             {
                 Subject = "SecurityCode",
                 BodyFormat = "Your security code is {0}"
             });
             manager.EmailService = new EmailService();
             manager.SmsService = new SmsService();
             var dataProtectionProvider = options.DataProtectionProvider;
             if (dataProtectionProvider != null)
             {
                 manager.UserTokenProvider =
                     new DataProtectorTokenProvider<KeyHubUser>(dataProtectionProvider.Create("ASP.NET Identity"));
             }
             return manager;
         }*/
    }

    // Configure the RoleManager used in the application. RoleManager is defined in the ASP.NET Identity core assembly
  /*  public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public ApplicationRoleManager(IRoleStore<IdentityRole,string> roleStore)
            : base(roleStore)
        {
        }

        public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context)
        {
            return new ApplicationRoleManager(new RoleStore<IdentityRole>(context.Get<DataContext>()));
        }
    }*/

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
