﻿using KeyHub.Model;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
namespace KeyHub.Data
{
    public class ApplicationDbContext : IdentityDbContext<AspIdentityUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
        }

        static ApplicationDbContext()
        {
            // Set the database intializer which is run once during application start
            // This seeds the database with admin user credentials and admin role
          //  Database.SetInitializer<ApplicationDbContext>(new ApplicationDbInitializer());
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }
}
