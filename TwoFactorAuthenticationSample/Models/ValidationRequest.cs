namespace TwoFactorAuthenticationSample.Models;

public record class ValidationRequest(string Token, string Code);
