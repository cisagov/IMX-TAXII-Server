/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror.method;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.git.mirror.GitHubRepo;
import com.cisa.taxii4j2.git.mirror.Mapping;

public interface TAXIIMirror {

	public static class MirrorState {

		private static final String filterKey = "filter";
		private static final String runningKey = "running";

		@JsonProperty(filterKey)
		private final GitHubRepo filter;

		@JsonProperty(runningKey)
		private final Set<UUID> running;

		@JsonCreator
		public MirrorState(@JsonProperty(value = filterKey, required = true) GitHubRepo filter,
				@JsonProperty(value = runningKey, required = true) Set<UUID> running) {
			super();
			this.filter = filter;
			this.running = running;
		}

		public GitHubRepo getFilter() {
			return filter;
		}

		public Set<UUID> getRunning() {
			return running;
		}

	}

	public MirrorState mirrorCreate(GitHubRepo filter);

	public MirrorState mirrorAdd(UUID uuid, Mapping mapping);

	public List<MirrorState> mirrorList();

	public MirrorState mirrorRead(UUID uuid);

	public MirrorState mirrorUpdate(UUID uuid);

	public MirrorState mirrorRemove(UUID uuid, UUID mUuid);

	public void mirrorRemove(UUID uuid);

	public JsonNode mirrorSchema(String id);

	public void start();

}
