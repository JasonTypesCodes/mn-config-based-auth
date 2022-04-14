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

import java.util.HashMap;
import java.util.Map;

import com.github.jasontypescodes.mn.configauth.config.ConfigAuthAccount;
import com.github.jasontypescodes.mn.configauth.config.ConfigAuthConfiguration;

import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;

/**
 * An {@code AuthenticationProvider} that uses
 * configuration to load account information.
 *
 * {@code config-based-auth.enabled} must explicitly be set to {@code true}
 */
@Singleton
@Requires(property = "config-based-auth.enabled", value = StringUtils.TRUE)
public class ConfigBasedAuthProvider implements AuthenticationProvider {

	private final ConfigAuthConfiguration config;
	private final Logger log = LoggerFactory.getLogger(ConfigBasedAuthProvider.class);

	private final Map<String, ConfigAuthAccount> accounts;

	/**
	 * Initializes this class with the provided configuration
	 *
	 * @param config The {@link com.github.jasontypescodes.mn.configauth.config.ConfigAuthConfiguration}
	 */
	public ConfigBasedAuthProvider(ConfigAuthConfiguration config) {
		this.config = config;
		this.accounts = new HashMap<>();
		log.debug("Initializing ConfigBasedAuthProvider...");
		if (config.isEnabled()) {
			for (String key : this.config.getAccounts().keySet()) {
				ConfigAuthAccount account = config.getAccounts().get(key);
				String identity = StringUtils.isEmpty(account.getIdentity()) ? key : account.getIdentity();
				log.debug("Found account '{}' with identity '{}'", key, identity);
				accounts.put(identity, account);
			}
		} else {
			log.error("Ignoring configured accounts due to config-based-auth.enabled not set to true.");
		}
	}

	/**
	 * Authenticates a request based on configured accounts
	 *
	 * @param httpRequest The {@code HttpRequest} for this request
	 * @param authRequest The {@code AuthenticationRequest} for this request
	 *
	 * @return A {@code Publisher} that will emit a single {@code AuthenticationResponse} if
	 *         authentication is successful and will otherwise emit an error.
	 */
	@Override
	public Publisher<AuthenticationResponse> authenticate(
		HttpRequest<?> httpRequest,
		AuthenticationRequest<?, ?> authRequest
	) {
		return Mono.<AuthenticationResponse>create(emitter -> {
			final String identity = (String) authRequest.getIdentity();

			final ConfigAuthAccount account = accounts.get(identity);

			final String logMessage =
				account == null ?
				"Unable to locate account for identity '{}'" :
				"Successfully located account for identity '{}'";

			log.debug(logMessage, identity);

			if (account != null && account.getSecret().equals(authRequest.getSecret())) {
				log.debug("'{}' authenticated successfully", identity);
				emitter.success(AuthenticationResponse.success(identity, account.getRoles(), account.getAttributes()));
			} else {
				log.debug("Authentication failed for '{}'", identity);
				emitter.error(new AuthenticationException(new AuthenticationFailed()));
			}
		});
	}
}
