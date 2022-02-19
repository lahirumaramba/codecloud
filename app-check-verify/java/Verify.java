/*
 * Copyright 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.company;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

public class Verify {
	public static void main(String[] args) {
		System.out.println("hello");
		String token = "X-Firebase-AppCheck";
		try {
			verify(token);
		} catch (Exception e) {
			System.out.println(e);
		}
	}

	public static void verify(String token) throws Exception {
		DecodedJWT jwt = JWT.decode(token);

		if (!jwt.getAlgorithm().equals("RS256")) {
			// Ensure the token's header uses the algorithm RS256
			throw new Exception("invalid algorithm");
		} else if (!jwt.getType().equals("JWT")) {
			// Ensure the token's header has type JWT
			throw new Exception("invalid type");
		}

		// Obtain the Firebase App Check Public Keys
		// Note: It is not recommended to hard code these keys as they rotate,
		// but you should cache them for up to 6 hours.
		JwkProvider provider = new JwkProviderBuilder(new URL("https://firebaseappcheck.googleapis.com/v1beta/jwks"))
				.cached(10, 6, TimeUnit.HOURS)
				.build();
		Jwk jwk = provider.get(jwt.getKeyId());

		Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
		JWTVerifier verifier = JWT.require(algorithm)
				// Ensure the token is issued by App Check
				.withIssuer(String.format("https://firebaseappcheck.googleapis.com/%s", PROJECT_NUMBER))
				// Ensure the token's audience matches your project
				.withAnyOfAudience(String.format("projects/%s", PROJECT_NUMBER))
				.build();

		try {
			jwt = verifier.verify(token);
		} catch (JWTVerificationException exception) {
			// invalid token
			throw exception;
		}

		// The token's subject will be the app ID, you may optionally filter against
		// an allow list
		String app_id = jwt.getSubject();
		System.out.println(app_id);
	}
}
