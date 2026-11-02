/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.Level;

import com.cisa.taxii4j2.a1.A1ClientBase;
import com.cisa.taxii4j2.a1.A1Endpoint;
import com.cisa.taxii4j2.auth.method.AuthEndpoint;
import com.cisa.taxii4j2.auth.method.BulkAdmin;
import com.cisa.taxii4j2.client.ClientEndpoint;
import com.cisa.taxii4j2.client.job.remote.ClientJobEndpoint;
import com.cisa.taxii4j2.client.job.remote.MISPClientJobEndpoint;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.ext.method.SchemaEndpoint;
import com.cisa.taxii4j2.git.mirror.GitHubRepo;
import com.cisa.taxii4j2.git.mirror.GitHubRepos;
import com.cisa.taxii4j2.git.mirror.method.impl.MirrorEndpoint;
import com.cisa.taxii4j2.graph.GraphEndpoint;
import com.cisa.taxii4j2.method.ValidateEndpoint;
import com.cisa.taxii4j2.method.logging.RequestLoggingFilter;
import com.cisa.taxii4j2.method.logging.ResponseLoggingFilter;
import com.cisa.taxii4j2.misp.MISPEndpoint;
import com.cisa.taxii4j2.mount.TAXIIMountEndpoint;
import com.cisa.taxii4j2.search.SearchEndpoint;
import com.cisa.taxii4j2.servlet.security.RBACSecurityHandler;
import com.cisa.taxii4j2.util.UtilEndpoint;

import jakarta.ws.rs.core.Response;

public class THMicroService extends MicroService {

	public THMicroService() throws IOException {
		super(new RBACSecurityHandler(), AuthEndpoint.class, TAXIIEndpoint.class, RequestLoggingFilter.class,
				ResponseLoggingFilter.class, MirrorEndpoint.class, A1Endpoint.class, SchemaEndpoint.class,
				TAXIIMountEndpoint.class, SearchEndpoint.class, GraphEndpoint.class, ClientEndpoint.class,
				ValidateEndpoint.class, PingEndpoint.class, UtilEndpoint.class, ClientJobEndpoint.class
				/*MISPEndpoint.class, MISPClientJobEndpoint.class*/);
	}

	public static void main(String[] argv) {

		try {

			TAXIIConfig.setArgs(argv);

			if (TAXIIConfig.getConfigs() == null) {
				System.err.println("at least one configuration file or resource MUST be specified!!!");
				System.exit(-1);
			}
			Configuration.configure(TAXIIConfig.getConfigs());

			THMicroService service = new THMicroService();
			service.start();

			List<String> rcs = TAXIIConfig.getRoots();
			if (rcs != null) {
				BulkAdmin bulkAdmin = TAXIIConfig.serviceLocator().getService(BulkAdmin.class);
				for (String rc : rcs) {
					try {
						bulkAdmin.configure(TAXIIConfig.readValue(rc, BulkAdmin.Configuration.class));
					} catch (Exception e) {
						logger.warn("Error creating api-root " + rc, e);
					}
				}
			}

			List<String> mirrors = TAXIIConfig.getMirrors();
			if (mirrors != null) {
				for (String mirror : mirrors) {
					try {
						GitHubRepos.create(TAXIIConfig.readValue(mirror, GitHubRepo.class));
					} catch (Exception e) {
						logger.warn("Error loading mirror " + mirror, e);
					}
				}
			}

			/*
			 * check A1
			 */
			try(A1ClientBase client = new A1ClientBase()) {
				Response response = client.getHelper(null);
				logger.info(String.format("A1 response status: %d", response.getStatus()));
			} catch (Exception e) {
				logger.log(Level.WARN, "A1 health check", e);
			}

			// Load the client job configurations from the database.
			TAXIIConfig.serviceLocator().getService(ClientJobEndpoint.class).load();

			service.join();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
