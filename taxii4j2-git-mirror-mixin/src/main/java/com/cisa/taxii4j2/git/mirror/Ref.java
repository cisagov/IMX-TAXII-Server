/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.JSON;

@JsonInclude(Include.NON_NULL)
public class Ref implements Comparable<Ref> {

	protected static final String uuidKey = "uuid";
	public static final String pathKey = "path";
	protected static final String shaKey = "sha";
	protected static final String idKey = "id";
	protected static final String indexKey = "index";
	protected static final String offsetKey = "offset";

	/**
	 * pointer back ActiveGHRepoFilter
	 */
	@JsonProperty(uuidKey)
	private final UUID uuid;

	/**
	 * path to GitHub blob entry
	 */
	@JsonProperty(pathKey)
	private final String path;

	/**
	 * SHA of blob
	 */
	@JsonProperty(shaKey)
	private final String sha;

	@JsonProperty(idKey)
	private String id;

	@JsonProperty(indexKey)
	private String index;

	@JsonProperty(offsetKey)
	private Integer offset;

	protected void setId(String id) {
		this.id = id;
	}

	protected void setIndex(String index) {
		this.index = index;
	}

	public UUID getUuid() {
		return uuid;
	}

	public String getPath() {
		return path;
	}

	public String getSha() {
		return sha;
	}

	@Override
	public int compareTo(Ref arg0) {
		return getPath().compareTo(arg0.getPath());
	}

	@JsonIgnore
	public String encodeId() {
		return String.format("%s %s", uuid, sha);
	}

	@Override
	public String toString() {
		try {
			return JSON.writeValueAsString(this);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	public void delete() {
		GitHubRepos.db().delete(id, index, ObjectNode.class);
	}

	public String getId() {
		return id;
	}

	public String getIndex() {
		return index;
	}

	public Integer getOffset() {
		return offset;
	}

	public Ref(@JsonProperty(value = uuidKey, required = true) UUID uuid,
			@JsonProperty(value = pathKey, required = true) String path,
			@JsonProperty(value = shaKey, required = false) String sha,
			@JsonProperty(value = idKey, required = true) String id,
			@JsonProperty(value = indexKey, required = true) String index,
			@JsonProperty(value = offsetKey, required = false) Integer offset) {
		super();
		this.uuid = uuid;
		this.path = path;
		this.sha = sha;
		this.id = id;
		this.index = index;
		this.offset = offset;
	}

	protected Ref(UUID uuid, String path, String sha) {
		this(uuid, path, sha, null, null, null);
	}

	public Ref(UUID uuid, String path, String id, String index) {
		this(uuid, path, null, id, index, null);
	}
}
