# Code samples on validating App Check Tokens

1. Fetch the JSON Web Key Set (JWKS) from the App Check key endpoint.
2. Verify the App Check token signature using the Key set.
3. If the signature verification passes, verify the headers and the data payload of the token to further confirm that the token is issued by Firebase App Check. Ensure the token has not expired.

See [Protecting Your Own Backend Services With Firebase App Check](https://medium.com/@lahirumaramba/protecting-your-own-backend-services-with-firebase-app-check-1daaef229f32) for more.
