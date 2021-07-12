using System.ComponentModel.DataAnnotations;

namespace JwtDemo.Models
{
    public class RevokeTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
