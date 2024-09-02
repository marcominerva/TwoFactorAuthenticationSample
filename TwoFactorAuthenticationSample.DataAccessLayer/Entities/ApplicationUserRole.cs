using Microsoft.AspNetCore.Identity;

namespace TwoFactorAuthenticationSample.DataAccessLayer.Entities;

public class ApplicationUserRole : IdentityUserRole<Guid>
{
    public virtual required ApplicationUser User { get; set; }

    public virtual required ApplicationRole Role { get; set; }
}
