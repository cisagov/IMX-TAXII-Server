/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.io.IOException;

import com.cisa.taxii4j2.auth.method.AuthEndpoint;
import com.cisa.taxii4j2.method.logging.RequestLoggingFilter;
import com.cisa.taxii4j2.method.logging.ResponseLoggingFilter;
import com.cisa.taxii4j2.servlet.security.RBACSecurityHandler;

public class AdminMicroService extends MicroService {

	public AdminMicroService() throws IOException {
		super(new RBACSecurityHandler(), AuthEndpoint.class, RequestLoggingFilter.class, ResponseLoggingFilter.class);
	}

	public static void main(String[] args) {

		if (args.length < 1) {
			System.err.println("at least one configuration file or resource MUST be specified!!!");
			System.exit(-1);
		}
		Configuration.configure(args);

		try {
			AdminMicroService service = new AdminMicroService();
			service.start();
			service.join();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
