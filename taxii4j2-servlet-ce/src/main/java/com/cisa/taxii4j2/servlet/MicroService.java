/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.ee9.nested.Request;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.ee9.nested.ErrorHandler;
import org.eclipse.jetty.ee9.servlet.FilterHolder;
import org.eclipse.jetty.ee9.servlet.ServletContextHandler;
import org.eclipse.jetty.ee9.servlet.ServletHolder;
import org.eclipse.jetty.ee9.servlets.CrossOriginFilter;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.spi.Container;
import org.glassfish.jersey.server.spi.ContainerLifecycleListener;
import org.glassfish.jersey.servlet.ServletContainer;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.User;
import com.cisa.taxii4j2.auth.method.AuthConfig;
import com.cisa.taxii4j2.auth.method.IssuerAdmin;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.auth.method.UserAdmin;
import com.cisa.taxii4j2.data.Discovery;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.impl.PropsHosts;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.servlet.security.TAXIISecurityHandler;
import com.cisa.taxii4j2.servlet.security.TAXIITrustManager;
import com.cisa.taxii4j2.servlet.store.DbBase;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.MediaType;

public class MicroService {

	public static final Logger logger = LogManager.getLogger(MicroService.class);

	private final ServletContextHandler context;
	private final Server server;
//	private SslContextFactory.Server sslContextFactory;
	private TAXIITrustManager trustManager;

	protected MicroService(URL url, ResourceConfig resourceConfig) throws IOException {
		this(url, resourceConfig, null);
	}

	protected MicroService(TAXIISecurityHandler securityHandler, Class<?>... endpoints) throws IOException {
		this(PropsHosts.instance().taxii(), null, securityHandler, endpoints);
	}

	protected MicroService(URL url, ResourceConfig resourceConfig, TAXIISecurityHandler securityHandler,
			Class<?>... endpoints) throws IOException {

		// These environment variables probably should go in TAXIIConfig or PropsHosts.
		String keystore = System.getenv("TAXII_KEYSTORE");
		String keystorePassword = System.getenv("TAXII_KEYSTORE_PASSWORD");
		String keystoreAlias = System.getenv("TAXII_KEYSTORE_ALIAS");
		String truststore = System.getenv("TAXII_TRUSTSTORE");
		String truststorePassword = System.getenv("TAXII_TRUSTSTORE_PASSWORD");

		if (resourceConfig == null) {
			resourceConfig = new ResourceConfig().register(PropsBinder.instance()).registerClasses(endpoints)
					.register(JacksonFeature.class).register(MultiPartFeature.class)
					.register(new ContainerLifecycleListener() {

						@Override
						public void onStartup(Container container) {

							/*
							 * UserAdmin creates a DbBase instance. To ensure that the DbBase is truly a
							 * singleton, need to use the Jersey HK2 service locator...
							 *
							 * We did use a different service locator to create the security handler, but I
							 * don't think we can do it here...
							 */

							final ServiceLocator serviceLocator = container.getApplicationHandler()
									.getInjectionManager().getInstance(ServiceLocator.class);
							TAXIIConfig.setServiceLocator(serviceLocator);

							AuthConfig authConfig = PropsAuthConfig.instance();
							UserAdmin userAdmin = serviceLocator.getService(UserAdmin.class);
							String user = authConfig.getTaxiiAdminUsername();
							String pass = authConfig.getTaxiiAdminPassword();
							try {
								userAdmin.upsertUser(new User(user, pass, Set.of(authConfig.getAdminRole(),
										authConfig.getUserRole(), authConfig.getRelayRole())), false);
							} catch (Exception e) {
								logger.fatal(String.format("Couldn't add bootstrap user \"%s\"/\"%s\"...bye!!!", user,
										pass));
								System.exit(-1);
							}
							securityHandler.setUserAdmin(userAdmin);

							IssuerAdmin issuerAdmin = serviceLocator.getService(IssuerAdmin.class);
							if (issuerAdmin != null) {
								securityHandler.setIssuerAdmin(issuerAdmin);
							}

							RootCollectionRead rcr = serviceLocator.getService(RootCollectionRead.class);
							if (rcr != null) {
								securityHandler.setRootCollectionRead(rcr);
							}

							if (trustManager != null) {
								if (truststore != null) {
									trustManager.init(serviceLocator.getService(DbBase.class), truststore, truststorePassword);
								} else {
									trustManager.init(serviceLocator.getService(DbBase.class), keystore, keystorePassword);
								}
							}

						}

						@Override
						public void onReload(Container container) {
							// TODO Auto-generated method stub

						}

						@Override
						public void onShutdown(Container container) {
							// TODO Auto-generated method stub

						}
					});
		}

		ServletContainer servletContainer = new ServletContainer(resourceConfig);

		server = new Server();

		int port = url.getPort();
		if (port < 0) {
			port = url.getDefaultPort();
		}

		ServerConnector connector = null;
		String protocol = url.getProtocol();
		if (protocol.equals("http")) {
			connector = new ServerConnector(server);
		} else if (protocol.equals("https")) {
			if (keystore == null) {
				System.err.println("No keystore supplied for https configuration, aborting...");
				System.exit(-1);
			}

			HttpConfiguration https = new HttpConfiguration();
			SecureRequestCustomizer src = new SecureRequestCustomizer();

			// TODO
			src.setSniHostCheck(false);

			https.addCustomizer(src);

			trustManager = new TAXIITrustManager();

			SslContextFactory.Server sslContextFactory = new SslContextFactory.Server() {

				@Override
				protected TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls)
						throws Exception {
					return new TrustManager[] { trustManager };
				}

			};
			sslContextFactory.setKeyStorePath(keystore);
			sslContextFactory.setKeyStorePassword(keystorePassword);
			if (keystoreAlias != null) {
				sslContextFactory.setCertAlias(keystoreAlias);
			}
			if (truststore != null) {
				sslContextFactory.setTrustStorePath(truststore);
				sslContextFactory.setTrustStorePassword(truststorePassword);
			}
			sslContextFactory.setWantClientAuth(true); // .setNeedClientAuth(true); // //

			connector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"),
					new HttpConnectionFactory(https));
		}
		connector.setPort(port);
		server.addConnector(connector);

		context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");

		ServletHolder holder = new ServletHolder(servletContainer);
		context.addServlet(holder, "/*");

		FilterHolder cors = context.addFilter(CrossOriginFilter.class, "/*",
				EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));

		cors.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, "GET,PUT,POST,DELETE,OPTIONS");
		cors.setInitParameter(CrossOriginFilter.ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, "*");
		cors.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, "*");
		cors.setInitParameter(CrossOriginFilter.ALLOW_CREDENTIALS_PARAM, "true");
		cors.setInitParameter(CrossOriginFilter.CHAIN_PREFLIGHT_PARAM, "false");

		ErrorHandler errorHandler = new ErrorHandler() {

			@Override
			protected void generateAcceptableResponse(Request baseRequest, HttpServletRequest request,
					HttpServletResponse response, int code, String message) throws IOException {
				response.setCharacterEncoding(StandardCharsets.UTF_8.name());
				response.setContentType(MediaType.APPLICATION_JSON);
				response.getWriter().write(JSON.writeValueAsString(new Error(message, code)));
				response.addHeader("User-Agent", Discovery.getInstance().getTitle());

				// Check if there is a throwable.
				Throwable th = (Throwable) request.getAttribute("jakarta.servlet.error.exception");
				if (th != null) {
					logger.error("Exception caught in jetty framework", th);
				}
			}

		};
		context.setErrorHandler(errorHandler);

		if (securityHandler != null) {
			context.setSecurityHandler(securityHandler);
		}

		server.setHandler(context);

	}

	public void start() throws Exception {
		server.start();
	}

	public void join() throws InterruptedException {
		server.join();
	}

}
