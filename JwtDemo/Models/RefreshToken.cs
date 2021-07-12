using Microsoft.EntityFrameworkCore;
using System;

namespace JwtDemo.Models
{
    [Owned]
    public class RefreshToken
    {
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public bool IsActive => Revoked == null && !IsExpired;
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Revoked { get; set; }
    }
}
