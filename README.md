# Two-Factor Authentication Sample

A sample that showcases how to implement Two-Factor authentication in a Web API using an external Authenticator app.

### Setup

- Open the [appsettings.json](https://github.com/marcominerva/TwoFactorAuthenticationSample/blob/master/TwoFactorAuthenticationSample/appsettings.json) file and set the connection string to the database
- Run the application

### How it works

- Call `/api/auth/register` to register a new user
- Call `/api/auth/login` to get a user token (this is not the JWT and expires after 5 minutes)
- Call `/api/auth/qrcode` with the user token to get the QR Code to add the account to the Authenticator app (note: the QR Code can be obtain only once, this is by design in this sample)
- Call `/api/auth/validate` with the user token and the OTP code to get the actual JWT

The built-in support for Two-Factor authentication in ASP.NET Core lacks some features. We may want to handle the other options that are provided by the [RFC 6238](http://tools.ietf.org/html/rfc6238), for example:

- Getting the time step of OTP verification to check that the code has only been validated once
- Defining the window of time steps that are considered [acceptable](http://tools.ietf.org/html/rfc6238#section-5.2) for validation

In this case, it is possible to take a look to [Otp.Net](https://github.com/kspearrin/Otp.NET) and use it to implement the [OTP verification](https://github.com/marcominerva/TwoFactorAuthenticationSample/blob/master/TwoFactorAuthenticationSample/Program.cs#L169-L174).