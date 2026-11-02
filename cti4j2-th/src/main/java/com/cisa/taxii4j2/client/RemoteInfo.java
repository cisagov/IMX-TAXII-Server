/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.client;

import java.io.IOException;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.auth.data.TCBasic;
import com.cisa.taxii4j2.auth.data.TCNone;
import com.cisa.taxii4j2.auth.data.TCOIDC;
import com.cisa.taxii4j2.auth.data.TCPKCS10;
import com.cisa.taxii4j2.auth.data.TCPKCS12;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

@JsonInclude(Include.NON_NULL)
@JsonDeserialize(using = RemoteInfo.Deserializer.class)
public abstract class RemoteInfo implements Comparable<RemoteInfo> {

	@JsonProperty(uuidKey)
	protected final UUID uuid;

	@JsonProperty(urlKey)
	protected final URL url;

	@JsonProperty(headersKey)
	protected final JsonNode headers;

	@JsonProperty(proxy_uriKey)
	protected final String proxy_uri;

	protected RemoteInfo(UUID uuid, URL url, JsonNode headers, String proxy_uri) {
		super();
		this.uuid = uuid;
		this.url = url;
		this.headers = headers;
		this.proxy_uri = proxy_uri;
	}

	public UUID getUuid() {
		return uuid;
	}

	@JsonIgnore
	public String getPassword() {
		return null;
	}

	@JsonIgnore
	public String getPkcs12() {
		return null;
	}

	public abstract TAXIICredentials credentials();

	public URL getUrl() {
		return url;
	}

	public JsonNode getHeaders() {
		return headers;
	}

	public String getProxy_uri() {
		return proxy_uri;
	}

	@Override
	public String toString() {
		try {
			return String.format("%s: %s", getClass().getSimpleName(), JSON.writeValueAsString(this));
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public static class None extends RemoteInfo {

		public None(UUID uuid, URL url, JsonNode headers, String proxy_uri) {
			super(uuid, url, headers, proxy_uri);
		}

		@Override
		public TAXIICredentials credentials() {
			return new TCNone();
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			int c = getClass().getName().compareTo(arg0.getClass().getName());
			if (c == 0) {
				None derived = None.class.cast(arg0);
				c = url.toString().compareTo(derived.url.toString());
			}
			return c;
		}

	}

	public static class Key extends RemoteInfo {

		public Key(UUID uuid) {
			super(uuid, null, null, null);
		}

		@Override
		public TAXIICredentials credentials() {
			throw new UnsupportedOperationException();
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			return uuid.compareTo(arg0.uuid);
		}

	}

	public static class Basic extends RemoteInfo {

		@JsonProperty(usernameKey)
		protected final String username;

		@JsonProperty(passwordKey)
		protected final String password;

		public Basic(UUID uuid, URL url, JsonNode headers, String proxy_uri, String username, String password) {
			super(uuid, url, headers, proxy_uri);
			this.username = username;
			this.password = password;
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			int c = getClass().getName().compareTo(arg0.getClass().getName());
			if (c == 0) {
				Basic derived = Basic.class.cast(arg0);
				c = url.toString().compareTo(derived.url.toString());
				if (c == 0) {
					c = username.compareTo(derived.username);
					if (c == 0) {
						c = password.compareTo(derived.password);
					}
				}
			}
			return c;
		}

		@Override
		public TAXIICredentials credentials() {
			return new TCBasic(username, password);
		}

	}

	public static class PKCS10 extends RemoteInfo {

		@JsonProperty(pkcs10Key)
		protected final String pkcs10;

		public PKCS10(UUID uuid, URL url, JsonNode headers, String proxy_uri, String pkcs10) {
			super(uuid, url, headers, proxy_uri);
			this.pkcs10 = pkcs10;
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			int c = getClass().getName().compareTo(arg0.getClass().getName());
			if (c == 0) {
				PKCS10 derived = PKCS10.class.cast(arg0);
				c = url.toString().compareTo(derived.url.toString());
				if (c == 0) {
					c = pkcs10.compareTo(derived.pkcs10);
				}
			}
			return c;
		}

		@Override
		public TAXIICredentials credentials() {
			return new TCPKCS10(pkcs10);
		}

	}

	public static class OIDC extends Basic {

		@JsonProperty(providerKey)
		protected final URL provider;

		public OIDC(UUID uuid, URL url, JsonNode headers, String proxy_uri, String username, String password,
				URL provider) {
			super(uuid, url, headers, proxy_uri, username, password);
			this.provider = provider;
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			int c = getClass().getName().compareTo(arg0.getClass().getName());
			if (c == 0) {
				OIDC derived = OIDC.class.cast(arg0);
				c = url.toString().compareTo(derived.url.toString());
				if (c == 0) {
					c = provider.toString().compareTo(derived.provider.toString());
					if (c == 0) {
						c = username.compareTo(derived.username);
						if (c == 0) {
							c = password.compareTo(derived.password);
						}
					}
				}
			}
			return c;
		}

		@Override
		public TAXIICredentials credentials() {
			return new TCOIDC(provider, username, password);
		}

	}

	public static class PKCS12 extends RemoteInfo {

		@JsonProperty(pkcs12Key)
		private final String pkcs12;

		@JsonProperty(passwordKey)
		private final String password;

		public PKCS12(UUID uuid, URL url, JsonNode headers, String proxy_uri, String pkcs12, String password) {
			super(uuid, url, headers, proxy_uri);
			this.pkcs12 = pkcs12;
			this.password = password;
		}

		@Override
		public TAXIICredentials credentials() {
			return new TCPKCS12();
		}

		@Override
		public int compareTo(RemoteInfo arg0) {
			int c = getClass().getName().compareTo(arg0.getClass().getName());
			if (c == 0) {
				PKCS12 derived = PKCS12.class.cast(arg0);
				c = url.toString().compareTo(derived.url.toString());
				if (c == 0) {
					c = pkcs12.compareTo(derived.pkcs12);
					if (c == 0) {
						c = password.compareTo(derived.password);
					}
				}
			}
			return c;
		}

		@Override
		public String getPkcs12() {
			return pkcs12;
		}

		@Override
		public String getPassword() {
			return password;
		}

	}

	public static final String urlKey = "url";
	public static final String headersKey = "headers";
	public static final String usernameKey = "username";
	public static final String passwordKey = "password";
	public static final String pkcs10Key = "pkcs10";
	public static final String providerKey = "provider";
	public static final String pkcs12Key = "pkcs12";
	public static final String uuidKey = "uuid";
	public static final String proxy_uriKey = "proxy_uri";

	private static String member(JsonNode root, String key) {
		JsonNode node = root.get(key);
		return (node != null) ? node.asText() : null;
	}

	public static MultivaluedMap<String, Object> headers(JsonNode root) {
		if (root == null) {
			return null;
		}
		if (!root.isObject()) {
			throw new IllegalArgumentException(
					String.format("RemoteInfo.headers: %s is not an object", root.toPrettyString()));
		}
		MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
		Iterator<Map.Entry<String, JsonNode>> iField = root.fields();
		while (iField.hasNext()) {
			Map.Entry<String, JsonNode> field = iField.next();
			String key = field.getKey();
			JsonNode value = field.getValue();
			if (value.isObject()) {
				throw new IllegalArgumentException(String.format("RemoteInfo.headers: value of %s is an object", key));
			}
			if (value.isArray()) {
				JsonNodeType type = null;
				Iterator<JsonNode> iValue = value.elements();
				while (iValue.hasNext()) {
					JsonNode node = iValue.next();
					if (type == null) {
						type = node.getNodeType();
					} else if (node.getNodeType() != type) {
						throw new IllegalArgumentException(
								String.format("RemoteInfo.headers: value of %s is heterogeneous array", key));
					}
					headers.add(key, value(node, type));
				}
			} else {
				headers.add(key, value(value, value.getNodeType()));
			}
		}
		return headers;
	}

	private static Object value(JsonNode node, JsonNodeType type) {
		switch (type) {
		case BOOLEAN:
			return node.asBoolean();
		case NUMBER:
			if (node.isDouble()) {
				return node.asDouble();
			}
			if (node.isInt()) {
				return node.asInt();
			}
			if (node.isLong()) {
				return node.asLong();
			}
			if (node.isBigInteger()) {
				return node.bigIntegerValue();
			}
			throw new IllegalArgumentException(
					String.format("RemoteInfo.headers: can't handle number value of %s", node));
		case STRING:
			return node.asText();
		default:
			throw new IllegalArgumentException(String.format("RemoteInfo.headers: can't handle type %s", type));
		}
	}

	public static RemoteInfo factory(JsonNode root) {
		return factory(member(root, uuidKey), member(root, urlKey), root.get(headersKey), member(root, proxy_uriKey),
				member(root, usernameKey), member(root, passwordKey), member(root, pkcs10Key),
				member(root, providerKey), member(root, pkcs12Key));
	}

	public static RemoteInfo factory(String _uuid, String _url, JsonNode headers, String proxy_uri, String username,
			String password, String pkcs10, String _provider, String pkcs12) {
		try {
			URL url = (_url != null) ? new URL(_url) : null;
			if (url == null) {
				throw new IllegalArgumentException("RemoteInfo.factory: url MUST be specified!");
			}
			UUID uuid = (_uuid != null) ? UUID.fromString(_uuid) : UUID.randomUUID();
			if (pkcs12 != null) {
				return new PKCS12(uuid, url, headers, proxy_uri, pkcs12, password);
			}
			URL provider = (_provider != null) ? new URL(_provider) : null;
			if (provider != null) {
				return new OIDC(uuid, url, headers, proxy_uri, username, password, provider);
			}
			if (pkcs10 != null) {
				return new PKCS10(uuid, url, headers, proxy_uri, pkcs10);
			}
			if (username != null) {
				return new Basic(uuid, url, headers, proxy_uri, username, password);
			}
			return new None(uuid, url, headers, proxy_uri);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static class Deserializer extends StdDeserializer<RemoteInfo> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(RemoteInfo.class);
		}

		@Override
		public RemoteInfo deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
			return factory(p.readValueAsTree());
		}

	}

}
