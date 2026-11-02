/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.mount;

import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.client.RemoteInfo;
import com.cisa.taxii4j2.client.TAXIIClient;
import com.cisa.taxii4j2.method.TAXII;

public interface TAXIIMount {

	@JsonInclude(Include.NON_NULL)
	public static class MountInfo {

		private static final String mpKey = "mp";
		private static final String infoKey = "info";

		@JsonProperty(mpKey)
		private final String mp;

		@JsonProperty(infoKey)
		private final RemoteInfo info;

		@JsonCreator
		public MountInfo(@JsonProperty(value = mpKey, required = true) String mp,
				@JsonProperty(value = infoKey, required = true) RemoteInfo info) {
			super();
			this.mp = mp;
			this.info = info;
		}

		public String getMp() {
			return mp;
		}

		public RemoteInfo getInfo() {
			return info;
		}

		public MountInfo(Map.Entry<String, TAXIIClient> mounted) {
			this(mounted.getKey(), mounted.getValue().getInfo());
		}

		@Override
		public String toString() {
			return JSON.convertValue(this, JsonNode.class).toPrettyString();
		}

	}

	@JsonInclude(Include.NON_NULL)
	public static class Mounted {

		public final String mountPoint;
		public final String fragment;
		@JsonIgnore
		public final TAXII taxii;

		public Mounted(String mountPoint, String fragment, TAXII taxii) {
			super();
			this.mountPoint = mountPoint;
			this.fragment = fragment;
			this.taxii = taxii;
		}

		@Override
		public String toString() {
			return JSON.convertValue(this, JsonNode.class).toPrettyString();
		}
	}

	public Set<Map.Entry<String, TAXIIClient>> mounts();

	public Map.Entry<String, TAXIIClient> taxii(String mp);

	public Mounted taxii(String mp, TAXII taxii);

	public Map.Entry<String, TAXIIClient> mount(MountInfo mountInfo);

	public Map.Entry<String, TAXIIClient> unmount(String mp);

}
