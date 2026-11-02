/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

@JsonInclude(Include.NON_NULL)
public class Mapping implements Comparable<Mapping> {

	public static final String schemaKey = "schema";

	private static final String includesKey = "includes";
	private static final String excludesKey = "excludes";
	private static final String cIdsKey = "cIds";
	private static final String typeKey = "type";
	private static final String relocateKey = "relocate";
	private static final String overridesKey = "overrides";

	@JsonIgnore
	private static RootCollectionRead rcr;

	@JsonIgnore
	private static String cId(String s) {
		if (rcr == null) {
			rcr = TAXIIConfig.serviceLocator().getService(RootCollectionRead.class);
		}
		return rcr.readCollection(s).getId();
	}

	@JsonProperty(GitHubRepo.uuidKey)
	private UUID uuid;

	@JsonProperty(typeKey)
	private final FilterType type;

	@JsonProperty(includesKey)
	private final Set<String> includes;

	@JsonProperty(excludesKey)
	private final Set<String> excludes;

	@JsonProperty(cIdsKey)
	private Set<String> cIds;

	@JsonProperty(relocateKey)
	private final Relocate relocate;

	@JsonProperty(overridesKey)
	private Set<String> overrides;

	@JsonCreator
	public Mapping(@JsonProperty(value = GitHubRepo.uuidKey, required = false) UUID uuid,
			@JsonProperty(value = typeKey, required = true) FilterType type,
			@JsonProperty(value = includesKey, required = true) Set<String> includes,
			@JsonProperty(value = excludesKey, required = false) Set<String> excludes,
			@JsonProperty(value = cIdsKey, required = false) Set<String> cIds,
			@JsonProperty(value = relocateKey, required = false) Relocate relocate,
			@JsonProperty(value = overridesKey, required = false) Set<String> overrides) {
		super();
		this.uuid = uuid;
		if (uuid == null) {
			this.uuid = UUID.randomUUID();
		}
		this.type = type;
		if ((includes == null) || includes.isEmpty()) {
			throw new IllegalArgumentException();
		}
		this.includes = Collections.unmodifiableSet(new TreeSet<>(includes));
		this.excludes = ((excludes != null) && !excludes.isEmpty())
				? Collections.unmodifiableSet(new TreeSet<>(excludes))
				: null;
		this.cIds = ((cIds != null) && !cIds.isEmpty()) ? cIds.stream().map(cId -> cId(cId)).collect(Collectors.toSet())
				: null;
		this.relocate = relocate;
		this.overrides = overrides;
	}

	public UUID getUuid() {
		return uuid;
	}

	public void setUuid(UUID uuid) {
		this.uuid = uuid;
	}

	public Relocate getRelocate() {
		return relocate;
	}

	public FilterType getType() {
		return type;
	}

	public Set<String> getcIds() {
		return (cIds != null) ? Collections.unmodifiableSet(cIds) : null;
	}

	public Set<String> getIncludes() {
		return includes;
	}

	public Set<String> getExcludes() {
		return excludes;
	}

	public Set<String> getOverrides() {
		return overrides;
	}

	@Override
	public int compareTo(Mapping arg0) {
		return uuid.compareTo(arg0.uuid);
	}

	@JsonIgnore
	public boolean isIncluded(String _path) {
		Path path = Paths.get(_path);
		boolean included = false;
		Iterator<String> iInclude = includes.iterator();
		while (!included && iInclude.hasNext()) {
			if (path.startsWith(iInclude.next())) {
				included = true;
				if (excludes != null) {
					Iterator<String> iExclude = excludes.iterator();
					while (included && iExclude.hasNext()) {
						if (path.startsWith(iExclude.next())) {
							included = false;
						}
					}
				}
			}
		}
		return included;
	}

	@JsonIgnore
	public Mapping normalize(RootCollectionRead rcr) {
		if (cIds != null) {
			cIds = cIds.stream().map(cId -> rcr.readCollection(cId).getId()).collect(Collectors.toSet());
		}
		return this;
	}

}
