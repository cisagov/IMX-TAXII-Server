/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.cti4j2.CTIMediaType;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.impl.CustomFields;
import com.cisa.taxii4j2.data.impl.DataUtils;

@JsonInclude(Include.NON_NULL)
public class ApiRoot extends CustomFields {

	protected static final String titleKey = "title";
	protected static final String versionsKey = "versions";
	protected static final String max_content_lengthKey = "max_content_length";
	protected static final String descriptionKey = "description";

	@JsonProperty(titleKey)
	private final String title;

	@JsonProperty(versionsKey)
	private final List<String> versions;

	@JsonProperty(max_content_lengthKey)
	private final JSON.Integer max_content_length;

	@JsonProperty(descriptionKey)
	private String description;

	public ApiRoot(String title) {
		this(title, Arrays.asList(CTIMediaType.TAXII2_1), 1<<16);
	}

	public ApiRoot(String title, List<String> versions, long max_content_length) {
		this(title, versions, JSON.Integer.valueOf(max_content_length), null);
	}

	public ApiRoot(ApiRoot src) {
		this(src.title, src.versions, src.max_content_length, src.description);
	}

	@JsonCreator
	public ApiRoot(@JsonProperty(value = titleKey, required = true) String title,
			@JsonProperty(value = versionsKey, required = true) List<String> versions,
			@JsonProperty(value = max_content_lengthKey, required = true) JSON.Integer max_content_length,
			@JsonProperty(value = descriptionKey, required = false) String description) {
		super(ApiRoot.class);
		this.title = title;
		this.versions = DataUtils.finalTidy(versions);
		this.max_content_length = max_content_length;
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

	public ApiRoot setDescription(String description) {
		this.description = description;
		return this;
	}

	public String getTitle() {
		return title;
	}

	public List<String> getVersions() {
		return versions;
	}

	public long getMax_content_length() {
		return max_content_length.getValue();
	}

}
