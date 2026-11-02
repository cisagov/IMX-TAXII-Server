/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.impl.FirstLast;

@JsonInclude(Include.NON_NULL)
public class Versions extends FirstLast {

	private static final String moreKey = "more";
	private static final String versionsKey = "versions";

	@JsonProperty(moreKey)
	private Boolean more;

	@JsonProperty(versionsKey)
	private List<String> versions;

	@JsonCreator
	public Versions(@JsonProperty(value = moreKey, required = false) Boolean more,
			@JsonProperty(value = versionsKey, required = false) List<String> versions) {
		this(more, versions, null, null);
	}

	public Versions(Boolean more, List<String> versions, Timestamp first, Timestamp last) {
		super(Versions.class);
		setMore(more);
		setVersions(versions);
		this.setFirstLast(first, last);
	}

	public Boolean getMore() {
		return more;
	}

	public Versions setMore(Boolean more) {
		this.more = ((more != null) && more) ? true : null;
		return this;
	}

	public List<String> getVersions() {
		return versions;
	}

	public Versions setVersions(List<String> versions) {
		if ((versions == null) || versions.isEmpty()) {
			clearFirstLast();
			this.versions = null;
			return this;
		}
		java.util.Collections.sort(versions);
		this.versions = versions;
		return this;
	}

}
