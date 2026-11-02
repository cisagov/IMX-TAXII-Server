/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.main;

import java.io.IOException;

import com.cisa.taxii4j2.client.ClientEndpoint;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.method.logging.RequestLoggingFilter;
import com.cisa.taxii4j2.method.logging.ResponseLoggingFilter;
import com.cisa.taxii4j2.servlet.Configuration;
import com.cisa.taxii4j2.servlet.MicroService;
import com.cisa.taxii4j2.servlet.PingEndpoint;
import com.cisa.taxii4j2.servlet.TAXIIEndpoint;
import com.cisa.taxii4j2.servlet.security.CESecurityHandler;

public class ProxyMicroService extends MicroService {

	public ProxyMicroService() throws IOException {
		super(new CESecurityHandler(), TAXIIEndpoint.class, RequestLoggingFilter.class, ResponseLoggingFilter.class,
				ClientEndpoint.class, PingEndpoint.class);
	}

	public static void main(String[] args) {

		try {

			TAXIIConfig.setArgs(args);

			if (TAXIIConfig.getConfigs() == null) {
				System.err.println("at least one configuration file or resource MUST be specified!!!");
				System.exit(-1);
			}
			Configuration.configure(TAXIIConfig.getConfigs());

			ProxyMicroService service = new ProxyMicroService();
			service.start();
			service.join();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
