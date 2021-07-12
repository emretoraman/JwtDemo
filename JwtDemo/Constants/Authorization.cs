namespace JwtDemo.Constants
{
    public class Authorization
    {
        public enum Role
        {
            Administrator,
            Moderator,
            User
        }

        public const string DefaultUsername = "user";
        public const string DefaultEmail = "user@jwtdemo.com";
        public const string DefaultPassword = "Pa$$w0rd.";
        public const Role DefaultRole = Role.User;
    }
}
