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

package com.github.jasontypescodes.mn.configauth.config;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.micronaut.core.annotation.Introspected;

/**
 * Holds account information provided from configuration
 */
@Introspected
public class ConfigAuthAccount {
	private String identity;
	private String secret = "";
	private List<String> roles = Collections.emptyList();
	private Map<String, Object> attributes = Collections.emptyMap();

	/**
	 * Retrieves the identity
	 * @return the identity
	 */
	public String getIdentity() {
		return this.identity;
	}

	/**
	 * Sets the identity
	 * @param identity the identity
	 */
	public void setIdentity(String identity) {
		this.identity = identity;
	}

	/**
	 * Retrieves the secret
	 * @return the secret
	 */
	public String getSecret() {
		return this.secret;
	}

	/**
	 * Sets the secret
	 * @param secret the secret
	 */
	public void setSecret(String secret) {
		this.secret = secret;
	}

	/**
	 * Retrieves the list of configured roles
	 * @return the list of configured roles
	 */
	public List<String> getRoles() {
		return this.roles;
	}

	/**
	 * Sets the configured roles
	 * @param roles a list of roles
	 */
	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	/**
	 * Retrieves a map of additional attributes associated with the account
	 * @return map of additional attributes
	 */
	public Map<String,Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Sets additional attributes associated with the account
	 * @param attributes a map of additional attributes
	 */
	public void setAttributes(Map<String,Object> attributes) {
		this.attributes = attributes;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof ConfigAuthAccount)) {
			return false;
		}
		ConfigAuthAccount configAuthAccount = (ConfigAuthAccount) o;
		return Objects.equals(identity, configAuthAccount.identity) && Objects.equals(secret, configAuthAccount.secret) && Objects.equals(roles, configAuthAccount.roles) && Objects.equals(attributes, configAuthAccount.attributes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(identity, secret, roles, attributes);
	}

	@Override
	public String toString() {
		return "{" +
			" identity='" + getIdentity() + "'" +
			", roles='" + getRoles() + "'" +
			", attributes='" + getAttributes() + "'" +
			"}";
	}
}
