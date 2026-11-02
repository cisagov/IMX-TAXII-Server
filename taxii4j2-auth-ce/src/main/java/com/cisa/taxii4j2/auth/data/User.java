/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;

@JsonInclude(Include.NON_NULL)
public class User implements Comparable<User> {

	protected final static Logger logger = LogManager.getLogger(User.class);

	protected static final String rolesKey = "roles";
	public static final String userKey = "user";
	private static final String passwordKey = "password";

	@JsonProperty(userKey)
	protected String user;

	@JsonProperty(passwordKey)
	protected String password;

	@JsonProperty(rolesKey)
	private Set<String> roles;

	@JsonCreator
	public User(@JsonProperty(value = userKey, required = true) String user,
			@JsonProperty(value = passwordKey, required = false) String password,
			@JsonProperty(value = rolesKey, required = false) java.util.Collection<String> roles) {
		super();
		this.user = user;
		this.password = password;
		if ((roles != null) && !roles.isEmpty()) {
			this.roles = new TreeSet<>(roles);
		}
	}

	@JsonIgnore
	public boolean isRole(String role) {
		return (roles != null) ? roles.contains(role) : false;
	}

	public String getUser() {
		return user;
	}

	public String getPassword() {
		return password;
	}

	private static MessageDigest md;
	static {
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}

	private static Matcher hashed = Pattern.compile("^MD5:[0-9A-F]{32}$").matcher("");
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 512; // bits
    private static final int SALT_LENGTH = 16; // bytes
    public static final String MD5_HASH = "MD5";
    public static final String PBKDF2_HASH = "PBKDF2";

	public static String salt() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_LENGTH];
		random.nextBytes(salt);
		return HexFormat.of().formatHex(salt);
	}

	public static String hash(String password, String salt) {
		if ((password == null) || (password.startsWith(PBKDF2_HASH))) {
			// We could check with a pattern matcher, like the MD5 version does.
			return password;
		}
		try {
			HexFormat hex = HexFormat.of();
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), hex.parseHex(salt), ITERATIONS, KEY_LENGTH);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
			return String.format("%s:%s:%s", PBKDF2_HASH, salt, hex.formatHex(factory.generateSecret(spec).getEncoded()));
		} catch (Exception e) {
			logger.error("Error generating PBKDF2 hash", e);
			return null;
		}
	}

	public static String hash(String password) {
		synchronized (hashed) {
			hashed.reset(password);
			if (hashed.matches()) {
				return password;
			}
		}
		StringBuilder hash = new StringBuilder();
		synchronized (md) {
			md.reset();
			for (byte b : md.digest(password.getBytes())) {
				hash.append(String.format("%02X", b & 0xff));
			}
		}
		return String.format("%s:%s", MD5_HASH, hash.toString());
	}

	public static String generatePassword() {
		return String.format("%08X", Math.round(Math.random() * 0xffffffffL));
	}

	synchronized public User setPassword(String password) {
		if ((password == null) || password.isEmpty()) {
			password = generatePassword();
		}
		this.password = hash(password, salt());
		return this;
	}

	@Override
	public int compareTo(User arg0) {
		return getUser().compareTo(arg0.getUser());
	}

	public Set<String> getRoles() {
		return roles;
	}

	public User addRole(String role) {
		if (roles == null) {
			roles = new TreeSet<>();
		}
		roles.add(role);
		return this;
	}

	public User removeRole(String role) {
		roles.remove(role);
		if (roles.isEmpty()) {
			roles = null;
		}
		return this;
	}

	@Override
	public String toString() {
		return JSON.convertValue(this, JsonNode.class).toPrettyString();
	}

}
