using Microsoft.EntityFrameworkCore;

namespace TwoFactorAuthenticationSample.DataAccessLayer;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : AuthenticationDbContext(options)
{
}
