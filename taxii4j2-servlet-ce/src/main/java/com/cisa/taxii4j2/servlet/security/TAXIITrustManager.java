/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.servlet.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.cisa.taxii4j2.servlet.store.DbBase;

/**
 * https://donneyfan.com/blog/dynamic-java-truststore-for-a-jax-ws-client
 * https://jcalcote.wordpress.com/2010/06/22/managing-a-dynamic-java-trust-store/
 */
public class TAXIITrustManager implements X509TrustManager {

	@JsonInclude(Include.NON_NULL)
	@JsonSerialize(using = TAXIITrustManager.Serializer.class)
	@JsonDeserialize(using = TAXIITrustManager.Deserializer.class)
	public static class Entry {

		public static final String aliasKey = "alias";
		public static final String certificateKey = "certificate";

		@JsonProperty(aliasKey)
		private final String alias;

		@JsonProperty(certificateKey)
		private final Certificate certificate;

		@JsonCreator
		public Entry(@JsonProperty(value = aliasKey, required = true) String alias,
				@JsonProperty(value = certificateKey, required = true) Certificate certificate) {
			super();
			this.alias = alias;
			this.certificate = certificate;
		}

		public String getAlias() {
			return alias;
		}

		public Certificate getCertificate() {
			return certificate;
		}

	}

	public static class Serializer extends StdSerializer<Entry> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(Entry.class);
		}

		@Override
		public void serialize(Entry value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeStartObject();
			gen.writeStringField(Entry.aliasKey, value.getAlias());
			String encoded = null;
			try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
				ObjectOutputStream oos = new ObjectOutputStream(bos);
				oos.writeObject(value.getCertificate());
				oos.flush();
				encoded = Base64.getEncoder().encodeToString(bos.toByteArray());
			}
			gen.writeStringField(Entry.certificateKey, encoded);
			gen.writeEndObject();
		}
	}

	public static class Deserializer extends StdDeserializer<Entry> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(Entry.class);
		}

		@Override
		public Entry deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
			JsonNode root = p.readValueAsTree();
			Certificate certificate = null;
			String encoded = root.get(Entry.certificateKey).asText();
			byte[] decoded = Base64.getDecoder().decode(encoded.getBytes());
			try (ByteArrayInputStream bis = new ByteArrayInputStream(decoded)) {
				certificate = (Certificate) new ObjectInputStream(bis).readObject();
			} catch (ClassNotFoundException e) {
				throw new IOException(e);
			}
			return new Entry(root.get(Entry.aliasKey).asText(), certificate);
		}

	}

	private X509TrustManager trustManager;
	private static final Logger logger = LogManager.getLogger(TAXIITrustManager.class);
	private DbBase db;
	private String index;
	public static final Map<String, TAXIITrustManager> instances = new HashMap<>();

	public TAXIITrustManager() {
		super();
	}

	public static TAXIITrustManager instance() {
		if (instances.size() != 1) {
			logger.warn("this may not be the trust manager you were looking for...");
		}
		return !instances.isEmpty() ? instances.values().iterator().next() : null;
	}

	public static TAXIITrustManager instance(String tag) {
		return (tag != null) ? instances.get(tag) : instance();
	}

	public void init(DbBase db, String keyStoreFile, String keyStorePassword) {

		if (instances.put(keyStoreFile, this) != null) {
			throw new IllegalStateException(String.format("TAXIITrustManager.init: duplicate tag %s", keyStoreFile));
		}

		this.db = db;
		index = db.createIndex(db.localizeIndexName(String.format("%s-%s", keyStoreFile, "certs")));

		try {

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

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
				in = getClass().getResourceAsStream(keyStoreFile);
			}
			if (in == null) {
				try {
					in = new ByteArrayInputStream(Base64.getDecoder().decode(keyStoreFile));
				} catch (IllegalArgumentException e) {
				}
			}

			if (in != null) {
				keyStore.load(in, (keyStorePassword != null) ? keyStorePassword.toCharArray() : null);
				in.close();
				Enumeration<String> iAlias = keyStore.aliases();
				while (iAlias.hasMoreElements()) {
					String alias = iAlias.nextElement();
					Certificate certificate = keyStore.getCertificate(alias);
					Entry entry = new Entry(alias, certificate);
					db.put(entry, index, alias, false);
				}
			} else {
				keyStore.load(null, null);
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new IllegalStateException(e);
		}

		reload();

	}

	@Override
	synchronized public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		trustManager.checkClientTrusted(chain, authType);
	}

	@Override
	synchronized public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		try {
			trustManager.checkServerTrusted(chain, authType);
		} catch (CertificateException cx) {
			// Development logic only. Trusts the incoming untrusted certificate.
			// addCertificate(chain[0]);
			// reloadTrustManager();
			// trustManager.checkServerTrusted(chain, authType);
		}
	}

	@Override
	synchronized public X509Certificate[] getAcceptedIssuers() {
		return trustManager.getAcceptedIssuers();
	}

	synchronized private void reload() {

		try {

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);

			db.list(index, Entry.class).forEach(entry -> {
				try {
					logger.debug(String.format("TAXIITrustManager.reload: Loading certificate %s", entry.getAlias()));
					keyStore.setCertificateEntry(entry.getAlias(), entry.getCertificate());
				} catch (KeyStoreException e) {
					logger.log(Level.FATAL, String.format("TAXIITrustManager.reload: %s", entry.getAlias()), e);
				}
			});

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);

			// Get the X509TrustManager from the Factory.
			for (TrustManager tm : tmf.getTrustManagers()) {
				if (tm instanceof X509TrustManager) {
					trustManager = (X509TrustManager) tm;
					return;
				}
			}

		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		throw new IllegalStateException("No X509TrustManager in TrustManagerFactory");

	}

	public void addCertificate(String alias, Certificate cert) {
		try {
			db.put(new Entry(alias, cert), index, alias, false);
			db.refresh(index);
			reload();
		} catch (Exception e) {
			logger.log(Level.WARN, String.format("TAXIITrustManager.addCertificate: %s", alias), e);
		}
	}

	public void removeCertificate(String alias) throws Exception {
		try {
			db.delete(alias, index, Entry.class);
			db.refresh(index);
			reload();
		} catch (Exception e) {
			logger.log(Level.WARN, String.format("TAXIITrustManager.removeCertificate: %s", alias), e);
		}
	}

}
