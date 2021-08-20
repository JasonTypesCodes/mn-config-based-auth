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
import java.util.Map;
import java.util.Objects;

import io.micronaut.context.annotation.ConfigurationProperties;

/**
 * Holds configuration information for Config Based Auth
 */
@ConfigurationProperties(ConfigAuthConfiguration.CONFIG_BASE)
public class ConfigAuthConfiguration {

	/**
	 * Constant of the base configuration key
	 */
	public static final String CONFIG_BASE = "config-based-auth";

	private boolean enabled = false;
	private Map<String, ConfigAuthAccount> accounts = Collections.emptyMap();

	/**
	 * Is this module enabled?
	 * @return true if enabled.  Defaults to false
	 */
	public boolean isEnabled() {
		return this.enabled;
	}

	/**
	 * Retrieves the enabled value
	 * @return true if enabled.  Defaults to false
	 */
	public boolean getEnabled() {
		return this.enabled;
	}

	/**
	 * Sets enabled
	 * @param enabled true if enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Retrieves a map of configured accounts.
	 *
	 * If the account configuration does not include an
	 * identity, the key provided in configuration will
	 * be considered the account identity
	 *
	 * @return the map of configured accounts
	 */
	public Map<String,ConfigAuthAccount> getAccounts() {
		return this.accounts;
	}

	/**
	 * Sets the configured accounts
	 *
	 * @param accounts a map of configured accounts
	 */
	public void setAccounts(Map<String,ConfigAuthAccount> accounts) {
		this.accounts = accounts;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof ConfigAuthConfiguration)) {
			return false;
		}
		ConfigAuthConfiguration configAuthConfiguration = (ConfigAuthConfiguration) o;
		return enabled == configAuthConfiguration.enabled && Objects.equals(accounts, configAuthConfiguration.accounts);
	}

	@Override
	public int hashCode() {
		return Objects.hash(enabled, accounts);
	}

}
