using System.ComponentModel.DataAnnotations;

namespace JwtDemo.Models
{
    public class AddRoleRequest
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
