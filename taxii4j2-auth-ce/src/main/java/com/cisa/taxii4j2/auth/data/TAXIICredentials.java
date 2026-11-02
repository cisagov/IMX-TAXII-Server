/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.lang.reflect.Method;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;

import com.cisa.taxii4j2.auth.method.UserAdmin;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

public abstract class TAXIICredentials {

	private static UserAdmin userAdmin;
	protected static Logger logger = LogManager.getLogger(TAXIICredentials.class);
	private static final Set<Class<? extends TAXIICredentials>> subTypes = new Reflections(
			"com.cisa.taxii4j2.auth.data").getSubTypesOf(TAXIICredentials.class);

	protected static UserAdmin userAdmin() {
		if (userAdmin == null) {
			userAdmin = TAXIIConfig.serviceLocator().getService(UserAdmin.class);
		}
		return userAdmin;
	}

	public static User getUser(String headerValue) {
		for(Class<? extends TAXIICredentials> subType : subTypes) {
			try {
				Method method = subType.getMethod("getUser", String.class);
				try {
					return (User) method.invoke(null, headerValue);
				} catch(Exception e) {

				}
			} catch (NoSuchMethodException | SecurityException e) {
				logger.warn(String.format("%s doesn't implement getUser()...", subType.getName()));
			}
		}
		return null;
	}

	public abstract String getHeaderValue();

}
