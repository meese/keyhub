namespace KeyHub.Data.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class id2 : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "AspIdentityUserIdentifier", c => c.String(maxLength: 40));
            AddColumn("dbo.AspNetUsers", "UserId", c => c.Int());
            CreateIndex("dbo.AspNetUsers", "UserId");
            AddForeignKey("dbo.AspNetUsers", "UserId", "dbo.Users", "UserId", cascadeDelete: true);
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.AspNetUsers", "UserId", "dbo.Users");
            DropIndex("dbo.AspNetUsers", new[] { "UserId" });
            DropColumn("dbo.AspNetUsers", "UserId");
            DropColumn("dbo.Users", "AspIdentityUserIdentifier");
        }
    }
}
