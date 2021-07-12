using Microsoft.AspNetCore.Identity;

namespace JwtDemo.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
