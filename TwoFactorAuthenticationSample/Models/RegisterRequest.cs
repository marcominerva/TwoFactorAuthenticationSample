namespace TwoFactorAuthenticationSample.Models;

public record class RegisterRequest(string FirstName, string LastName, string Email, string Password);
