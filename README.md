# Two-Factor Authentication Sample

A sample that showcases how to implement two-factor authentication in a Web API using an external Authenticator app.

### Setup

- Open the [appsettings.json](https://github.com/marcominerva/TwoFactorAuthenticationSample/blob/master/TwoFactorAuthenticationSample/appsettings.json) file and set the connection string to the database
- Run the application

### How it works

- Call `/api/auth/register` to register a new user
- Call `/api/auth/login` to get a user token (this is not the JWT and expires after 5 minutes)
- Call `/api/auth/qrcode` with the user token to get the QR Code to add the account to the Authenticator app (note: the QR Code can be obtain only once, this is by design in this sample)
- Call `/api/auth/validate` with the user token and the OTP code to get the actual JWT
