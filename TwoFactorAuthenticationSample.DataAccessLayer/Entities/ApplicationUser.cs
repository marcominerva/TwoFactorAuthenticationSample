using Microsoft.AspNetCore.Identity;

namespace TwoFactorAuthenticationSample.DataAccessLayer.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public required string FirstName { get; set; }

    public required string LastName { get; set; }

    public virtual ICollection<ApplicationUserRole> UserRoles { get; set; } = [];
}
