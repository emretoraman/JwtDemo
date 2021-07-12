using JwtDemo.Models;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;
using static JwtDemo.Constants.Authorization;

namespace JwtDemo.Data
{
    public class ApplicationDbContextSeed
    {
        public static async Task SeedEssentials(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            foreach (string role in typeof(Role).GetEnumNames())
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }

            if (!userManager.Users.Any())
            {
                ApplicationUser user = new()
                {
                    UserName = DefaultUsername,
                    Email = DefaultEmail,
                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true
                };
                await userManager.CreateAsync(user, DefaultPassword);
                await userManager.AddToRoleAsync(user, DefaultRole.ToString());
                await userManager.AddToRoleAsync(user, Role.Administrator.ToString());
            }
        }
    }
}
