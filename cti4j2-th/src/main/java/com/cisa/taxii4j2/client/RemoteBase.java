/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.util.JacksonFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.cisa.cti4j2.CTIMediaType;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ContextResolver;

public class RemoteBase implements AutoCloseable {

	public static class TAXIIJsonProvider extends JacksonJsonProvider {

		private static final Set<MediaType> taxii = Set.of(
				new MediaType(CTIMediaType.MIME_TYPE, CTIMediaType.TAXII_SUBTYPE), new MediaType(CTIMediaType.MIME_TYPE,
						CTIMediaType.TAXII_SUBTYPE, Map.of("version", CTIMediaType.SPEC_VERSION)));

		public TAXIIJsonProvider() {
			super();

			StreamReadConstraints constraints = StreamReadConstraints.builder().maxStringLength(100_000_000).build();

			JsonFactory factory = new JsonFactory();
			factory.setStreamReadConstraints(constraints);

			super.setMapper(new ObjectMapper(factory));
		}

		@Override
		protected boolean hasMatchingMediaType(MediaType mediaType) {
			return taxii.contains(mediaType) ? true : super.hasMatchingMediaType(mediaType);
		}

	}

	private final Client client;
	protected final WebTarget target;

	/*
	 * These are from the perspective of the web service (i.e. check the JAX-RS
	 * annotations).
	 */
	protected final String consumes;
	protected final String produces;

	private final MultivaluedMap<String, Object> headers;

	public RemoteBase(String url, String consumes, String produces, MultivaluedMap<String, Object> headers,
			String proxy_uri, String keyStoreFile, String keyStorePassword) throws MalformedURLException {
		this(new URL(url), consumes, produces, headers, proxy_uri, keyStoreFile, keyStorePassword);
	}

	public RemoteBase(String url, String consumes, String produces, MultivaluedMap<String, Object> headers)
			throws MalformedURLException {
		this(new URL(url), consumes, produces, headers, null, null, null);
	}

	public RemoteBase(URL url, String consumes, String produces, MultivaluedMap<String, Object> headers) {
		this(url, consumes, produces, headers, null, null, null);
	}

	public RemoteBase(URL url, String consumes, String produces, MultivaluedMap<String, Object> headers,
			String proxy_uri, String keyStoreFile, String keyStorePassword) {
		super();

		this.consumes = consumes;
		this.produces = produces;
		this.headers = headers;

		ClientConfig config = new ClientConfig().property(ClientProperties.FEATURE_AUTO_DISCOVERY_DISABLE, true);
		if (proxy_uri != null) {
			config = config.property(ClientProperties.PROXY_URI, proxy_uri);
		}
		ClientBuilder builder = ClientBuilder.newBuilder().withConfig(config);
		if (url.getProtocol().equals("https")) {

			TrustManager[] certs = new TrustManager[] { new X509TrustManager() {

				@Override
				public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				}

				@Override
				public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}

			} };

			KeyManager[] kms = null;
			if (keyStoreFile != null) {
				try {

					KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

					/*
					 * try, in order, external file, system resource, class resource, base64
					 * literal...
					 */
					InputStream in = null;
					try {
						in = Files.newInputStream(Paths.get(keyStoreFile));
					} catch (Exception e) {

					}
					if (in == null) {
						in = ClassLoader.getSystemResourceAsStream(keyStoreFile);
					}
					if (in == null) {
						in = RemoteBase.class.getResourceAsStream(keyStoreFile);
					}
					if (in == null) {
						/*
						 * this will throw IllegalArgumentException if it doesn't decode...
						 */
						in = new ByteArrayInputStream(Base64.getDecoder().decode(keyStoreFile));
					}
					keystore.load(in, keyStorePassword.toCharArray());
					in.close();

					KeyManagerFactory keyManagerFactory = KeyManagerFactory
							.getInstance(KeyManagerFactory.getDefaultAlgorithm());
					keyManagerFactory.init(keystore, keyStorePassword.toCharArray());
					kms = keyManagerFactory.getKeyManagers();

				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
						| IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new IllegalArgumentException(e);
				}
			}

			try {
				SSLContext sslContext = SSLContext.getInstance("TLS");
				sslContext.init(kms, certs, new SecureRandom());
				builder = builder.sslContext(sslContext).hostnameVerifier((x, y) -> true);
			} catch (KeyManagementException | NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new IllegalArgumentException(e);
			}

		}
		client = builder.register(JacksonFeature.class).register(MultiPartFeature.class)
				.register(new TAXIIJsonProvider()).build();
		target = client.target(url.toString());
	}

	public RemoteBase(RemoteInfo info, String consumes, String produces) {
		this(info.getUrl(), consumes, produces, RemoteInfo.headers(info.headers), info.getProxy_uri(), info.getPkcs12(),
				info.getPassword());
	}

	public WebTarget target() {
		return target;
	}

	public WebTarget target(String url) {
		return client.target(url);
	}

	public Invocation.Builder paths(MultivaluedMap<String, String> queryParams, String... paths) {
		return paths(target, headers, produces, queryParams, paths);
	}

	public Invocation.Builder paths(WebTarget target, MultivaluedMap<String, Object> headers, String produces,
			MultivaluedMap<String, String> queryParams, String... paths) {
		for (String path : paths) {
			target = target.path(path);
		}
		if (queryParams != null) {
			for (Map.Entry<String, List<String>> q : queryParams.entrySet()) {
				target = target.queryParam(q.getKey(), q.getValue().toArray(Object[]::new));
			}
		}
		Invocation.Builder builder = (produces != null) ? target.request(produces) : target.request();
		if (headers != null) {
			builder = builder.headers(headers);
		}
		return builder;
	}

	public <T> T postHelper(Object entity, Class<T> clazz, MultivaluedMap<String, String> queryParams,
			String... paths) {
		return postHelper(entity, queryParams, paths).readEntity(clazz);
	}

	public <T, R> R postHelper(Entity<T> entity, Class<R> clazz, MultivaluedMap<String, String> queryParams,
			String... paths) {
		return postHelper(entity, queryParams, paths).readEntity(clazz);
	}

	public Response postHelper(Object entity, MultivaluedMap<String, String> queryParams, String... paths) {
		return postHelper(Entity.entity(entity, consumes), queryParams, paths);
	}

	public <T> Response postHelper(Entity<T> entity, MultivaluedMap<String, String> queryParams, String... paths) {
		Invocation invocation = paths(queryParams, paths).header(HttpHeaders.CONTENT_TYPE, entity.getMediaType())
				.buildPost(entity);
		return invocation.invoke();
	}

	public <T> T getHelper(Class<T> clazz, MultivaluedMap<String, String> queryParams, String... paths) {
		return getHelper(queryParams, paths).readEntity(clazz);
	}

	public Response getHelper(MultivaluedMap<String, String> queryParams, String... paths) {
		Invocation invocation = paths(queryParams, paths).buildGet();
		return invocation.invoke();
	}

	public Error deleteHelper(MultivaluedMap<String, String> queryParams, String... paths) {
		Invocation invocation = paths(queryParams, paths).buildDelete();
		return invocation.invoke(Error.class);
	}

	public String getConsumes() {
		return consumes;
	}

	public String getProduces() {
		return produces;
	}

	@Override
	public void close() throws Exception {
		client.close();
	}

}
