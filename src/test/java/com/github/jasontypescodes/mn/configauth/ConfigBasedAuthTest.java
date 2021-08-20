/*
 * Copyright 2021 Jason Schindler
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

package com.github.jasontypescodes.mn.configauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.github.jasontypescodes.mn.configauth.config.ConfigAuthAccount;
import com.github.jasontypescodes.mn.configauth.config.ConfigAuthConfiguration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.env.PropertySource;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.endpoints.introspection.IntrospectionResponse;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

@SuppressWarnings("unchecked")
public class ConfigBasedAuthTest {
	String VALID_ACCOUNT = "validAccount";
	String VALID_SECRET = "validSecret";
	String ALT_ID_ACCOUNT = "alternateIdAccount";
	String ALT_ID_IDENTITY = "batman@test.test";
	String ALT_ID_SECRET = "@lfr3d";
	String TEST_ATT_KEY = "someAttKey";
	String TEST_ATT_VAL = "someAttVal";

	String ROLE1 = "ROLE_1";
	String ROLE2 = "ROLE_2";
	String ROLE3 = "ROLE_3";

	PropertySource CONFIG_BASE = PropertySource.of("base", Map.of(
		"micronaut.security", Map.of(
			"enabled", "true",
			"authentication", "bearer",
			"token.jwt.signatures.secret.generator.secret", "testsecret"
		),
		"config-based-auth", Map.of(
			"accounts", Map.of(
				VALID_ACCOUNT, Map.of(
					"roles", Set.of(ROLE1, ROLE3),
					"secret", VALID_SECRET,
					"attributes", Map.of(
						TEST_ATT_KEY, TEST_ATT_VAL
					)
				),
				ALT_ID_ACCOUNT, Map.of(
					"identity", ALT_ID_IDENTITY,
					"secret", ALT_ID_SECRET,
					"roles", Set.of(ROLE2)
				)
			)
		)
	), 1);

	PropertySource ENABLED = PropertySource.of("enabled", Map.of(
		"config-based-auth", Map.of(
			"enabled", "true"
		)
	), 2);

	UsernamePasswordCredentials validLogin = new UsernamePasswordCredentials(VALID_ACCOUNT, VALID_SECRET);

	private EmbeddedServer server;

	@AfterEach
	public void cleanup() {
		if (server != null && server.isRunning()) {
			server.stop();
		}
	}

	@Test
	public void loadsConfig() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		ConfigAuthConfiguration config = server.getApplicationContext().getBean(ConfigAuthConfiguration.class);
		assertNotNull(config);

		Map<String, ConfigAuthAccount> accounts = config.getAccounts();
		assertNotNull(accounts);

		ConfigAuthAccount anAccount = accounts.get(VALID_ACCOUNT);

		assertNotNull(anAccount);

		assertEquals(VALID_SECRET, anAccount.getSecret());
		assertEquals(2, anAccount.getRoles().size());
		assertTrue(anAccount.getRoles().containsAll(Set.of(ROLE1, ROLE3)));
		assertEquals(TEST_ATT_VAL, anAccount.getAttributes().get(TEST_ATT_KEY));
	}

	@Test
	public void isDisabledByDefault() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE)
			.run(EmbeddedServer.class);

		assertFalse(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpClientResponseException error = assertThrows(HttpClientResponseException.class, () -> {
			client.toBlocking().exchange(HttpRequest.POST("/login", validLogin));
		});

		assertEquals(HttpStatus.UNAUTHORIZED, error.getStatus());
	}

	@Test
	public void allowsConfiguredUser() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		assertTrue(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpResponse<AccessRefreshToken> res = client.toBlocking()
			.exchange(HttpRequest.POST("/login", validLogin), AccessRefreshToken.class);

		assertEquals(HttpStatus.OK, res.getStatus());

		AccessRefreshToken body = res.body();

		String token = body.getAccessToken();

		assertNotNull(token);

		HttpResponse<IntrospectionResponse> infoResponse = client.toBlocking()
			.exchange(HttpRequest.GET("/token_info").bearerAuth(token), IntrospectionResponse.class);

		assertEquals(HttpStatus.OK, infoResponse.getStatus());

		IntrospectionResponse details = infoResponse.body();

		assertNotNull(details);

		assertEquals(TEST_ATT_VAL, details.getExtensions().get(TEST_ATT_KEY));

		List<String> roles = (List<String>) details.getExtensions().get("roles");

		assertEquals(2, roles.size());
		assertTrue(roles.contains(ROLE1));
		assertTrue(roles.contains(ROLE3));
	}

	@Test
	public void failsWithBadSecret() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		assertTrue(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpClientResponseException error = assertThrows(HttpClientResponseException.class, () -> {
			client.toBlocking().exchange(
				HttpRequest.POST("/login", new UsernamePasswordCredentials(VALID_ACCOUNT, "badPass"))
			);
		});

		assertEquals(HttpStatus.UNAUTHORIZED, error.getStatus());
	}

	@Test
	public void failsWithUnknownAccount() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		assertTrue(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpClientResponseException error = assertThrows(HttpClientResponseException.class, () -> {
			client.toBlocking().exchange(
				HttpRequest.POST("/login", new UsernamePasswordCredentials("some.user", VALID_SECRET))
			);
		});

		assertEquals(HttpStatus.UNAUTHORIZED, error.getStatus());
	}

	@Test
	public void recognizesAlternateIdentity() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		assertTrue(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpClientResponseException error = assertThrows(HttpClientResponseException.class, () -> {
			client.toBlocking().exchange(
				HttpRequest.POST("/login", new UsernamePasswordCredentials(ALT_ID_ACCOUNT, ALT_ID_SECRET))
			);
		});

		assertEquals(HttpStatus.UNAUTHORIZED, error.getStatus());

		HttpResponse<AccessRefreshToken> res = client.toBlocking()
			.exchange(
				HttpRequest.POST("/login", new UsernamePasswordCredentials(ALT_ID_IDENTITY, ALT_ID_SECRET)),
				AccessRefreshToken.class
			);

		assertEquals(HttpStatus.OK, res.getStatus());

		AccessRefreshToken body = res.body();

		String token = body.getAccessToken();

		assertNotNull(token);

		HttpResponse<IntrospectionResponse> infoResponse = client.toBlocking()
			.exchange(HttpRequest.GET("/token_info").bearerAuth(token), IntrospectionResponse.class);

		assertEquals(HttpStatus.OK, infoResponse.getStatus());

		IntrospectionResponse details = infoResponse.body();

		assertNotNull(details);

		List<String> roles = (List<String>) details.getExtensions().get("roles");

		assertEquals(1, roles.size());
		assertTrue(roles.contains(ROLE2));
	}

	@Test
	public void failsWithMismatchedCreds() {
		server = ApplicationContext.builder()
			.mainClass(EmbeddedServer.class)
			.propertySources(CONFIG_BASE, ENABLED)
			.run(EmbeddedServer.class);

		assertTrue(server.getApplicationContext().containsBean(ConfigBasedAuthProvider.class));

		HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL());

		HttpClientResponseException error = assertThrows(HttpClientResponseException.class, () -> {
			client.toBlocking().exchange(
				HttpRequest.POST("/login", new UsernamePasswordCredentials(ALT_ID_IDENTITY, VALID_SECRET))
			);
		});

		assertEquals(HttpStatus.UNAUTHORIZED, error.getStatus());
	}
}
