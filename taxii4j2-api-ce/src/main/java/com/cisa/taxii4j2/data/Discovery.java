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
import com.cisa.taxii4j2.data.impl.CustomFields;
import com.cisa.taxii4j2.data.impl.DataUtils;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

@JsonInclude(Include.NON_NULL)
public class Discovery extends CustomFields {

	private static final String titleKey = "title";
	private static final String descriptionKey = "description";
	private static final String contactKey = "contact";
	private static final String defaultKey = "default";
	private static final String api_rootsKey = "api_roots";

	@JsonProperty(titleKey)
	private final String title;

	@JsonProperty(descriptionKey)
	private String description;

	@JsonProperty(contactKey)
	private String contact;

	@JsonProperty(defaultKey)
	private String _default;

	@JsonProperty(api_rootsKey)
	private List<String> api_roots;

	public Discovery(String title) {
		this(title, null, null, null, null);
	}

	public Discovery(Discovery src, List<String> api_roots) {
		this(src.title, src.description, src.contact, src._default, api_roots);
	}

	@JsonCreator
	public Discovery(@JsonProperty(value = titleKey, required = true) String title,
			@JsonProperty(value = descriptionKey, required = false) String description,
			@JsonProperty(value = contactKey, required = false) String contact,
			@JsonProperty(value = defaultKey, required = false) String _default,
			@JsonProperty(value = api_rootsKey, required = false) List<String> api_roots) {
		super(Discovery.class);
		this.title = title;
		this.description = description;
		this.contact = contact;
		this._default = _default;
		this.api_roots = DataUtils.tidy(api_roots);
	}

	public String getDescription() {
		return description;
	}

	public Discovery setDescription(String description) {
		this.description = description;
		return this;
	}

	public String getContact() {
		return contact;
	}

	public Discovery setContact(String contact) {
		this.contact = contact;
		return this;
	}

	public String get_default() {
		return _default;
	}

	public Discovery set_default(String _default) {
		this._default = _default;
		return this;
	}

	public List<String> getApi_roots() {
		return api_roots;
	}

	public Discovery setApi_roots(List<String> api_roots) {
		this.api_roots = DataUtils.tidy(api_roots);
		return this;
	}

	public String getTitle() {
		return title;
	}

	synchronized public static Discovery getInstance() {
		return TAXIIConfig.discovery();
	}


}
