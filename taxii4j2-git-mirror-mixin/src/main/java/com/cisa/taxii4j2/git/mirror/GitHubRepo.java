/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Consumer;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.git.mirror.method.impl.DbTaxiiRef;
import com.cisa.taxii4j2.servlet.store.DbBase;

@JsonInclude(Include.NON_NULL)
@JsonDeserialize(using = GitHubRepo.Deserializer.class)
public abstract class GitHubRepo {

	public static final Logger logger = GitHubRepos.logger;

	private static final String mappingsKey = "mappings";
	private static final String shaKey = "sha";

	public static final String uuidKey = "uuid";

	private static final String masterKey = "master";
	private static final String update_rateKey = "update_rate";

	@JsonProperty(update_rateKey)
	private String update_rate;

	@JsonProperty(masterKey)
	private final String master;

	@JsonProperty(shaKey)
	private String sha;

	public String getSha() {
		return sha;
	}

	public void setSha(String sha) {
		this.sha = sha;
	}

	private static class Key extends Mapping {

		private Key(UUID uuid) {
			super(uuid, null, Collections.singleton(""), null, null, null, null);
		}

	}

	private static GitHubRepo factory(JsonNode root) {
		GitHubRepo gh = null;
		if (root.get(GitHubRepoJGit.pathKey) != null) {
			gh = new GitHubRepoJGit(root);
		} else {
			gh = new GitHubRepoApi(root);
		}
		JsonNode sha = root.get(shaKey);
		gh.sha = (sha != null) ? sha.asText() : null;
		JsonNode mappings = root.get(mappingsKey);
		if (mappings != null) {
			Iterator<JsonNode> iMapping = mappings.iterator();
			while (iMapping.hasNext()) {
				gh.add(JSON.convertValue(iMapping.next(), Mapping.class));
			}
		}
		return gh;
	}

	public static class Deserializer extends StdDeserializer<GitHubRepo> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(GitHubRepo.class);
		}

		@Override
		public GitHubRepo deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
			return factory(p.readValueAsTree());
		}

	}

	@JsonProperty(mappingsKey)
	private Set<Mapping> mappings;

	@JsonProperty(uuidKey)
	private UUID uuid;

	public UUID getUuid() {
		return uuid;
	}

	private static final String defaultRemote = "origin/master";

	@JsonCreator
	public GitHubRepo(@JsonProperty(value = masterKey, required = false) String remote,
			@JsonProperty(value = uuidKey, required = false) UUID uuid,
			@JsonProperty(value = shaKey, required = false) String sha,
			@JsonProperty(value = mappingsKey, required = false) Set<Mapping> mappings,
			@JsonProperty(value = update_rateKey, required = false) String update_rate) {
		super();
		this.master = (remote != null) ? remote : defaultRemote;
		this.uuid = uuid;
		if (uuid == null) {
			uuid = UUID.randomUUID();
		}
		this.sha = sha;
		this.mappings = ((mappings != null) && !mappings.isEmpty()) ? new TreeSet<>(mappings) : null;
		this.update_rate = update_rate;
	}

	public String getUpdate_rate() {
		return update_rate;
	}

	protected GitHubRepo(JsonNode root) {
		super();
		JsonNode uuid = root.get(uuidKey);
		this.uuid = (uuid != null) ? UUID.fromString(uuid.asText()) : UUID.randomUUID();
		JsonNode master = root.get(masterKey);
		this.master = (master != null) ? master.asText() : defaultRemote;
		JsonNode update_rate = root.get(update_rateKey);
		this.update_rate = (update_rate != null) ? update_rate.asText() : null;
	}

	public String getMaster() {
		return master;
	}

	@JsonIgnore
	boolean add(Mapping mapping) {
		if (mappings == null) {
			mappings = new TreeSet<>();
		}
		return mappings.add(mapping);
	}

	@JsonIgnore
	boolean remove(UUID uuid) {
		boolean removed = false;
		if (mappings != null) {
			removed = mappings.remove(new Key(uuid));
		}
		if (removed && mappings.isEmpty()) {
			mappings = null;
		}
		return removed;
	}

	@JsonIgnore
	Mapping get(UUID uuid) {
		if (mappings == null) {
			return null;
		}
		final Mapping key = new Key(uuid);
		Optional<Mapping> mapping = mappings.stream().filter(m -> m.compareTo(key) == 0).findAny();
		return mapping.isPresent() ? mapping.get() : null;
	}

	public Set<Mapping> getMappings() {
		return (mappings != null) ? Collections.unmodifiableSet(mappings) : null;
	}

	@JsonIgnore
	Mapping findMapping(String path) {
		if ((path == null) || (mappings == null)) {
			return null;
		}
		Optional<Mapping> mapping = mappings.stream().filter(m -> m.isIncluded(path)).findAny();
		return mapping.isPresent() ? mapping.get() : null;
	}

	protected abstract void create(Mapping mapping);

	public abstract void update();

	public abstract void update(Mapping mapping);

	public abstract boolean hasChanged();

	protected static Set<String> indices(Mapping mapping) {
		Set<String> indices = null;
		switch (mapping.getType()) {
		case OBJECT:
			indices = GitHubRepos.dbTaxii().allObjectIndices();
			break;
		case SCHEMA:
			indices = Collections.singleton(GitHubRepos.schemaIndex());
			break;
		default:
			break;

		}
		return indices;
	}

	protected void delete(Mapping mapping) {
		Set<String> indices = indices(mapping);
		UUID uuid = mapping.getUuid();
		DbBase db = GitHubRepos.db();
		while (true) {
			Set<String> refresh = new HashSet<>();
			int n = forEachRef(uuid, null, indices, 0, o -> {
				o.delete();
				refresh.add(o.getIndex());
			});
			if (n == 0) {
				return;
			}
			db.refresh(refresh.toArray(String[]::new));
		}
	}

	@JsonIgnore
	boolean isValid() {
		if (mappings == null) {
			return true;
		}
		for (Mapping m0 : mappings) {
			for (Mapping m1 : mappings) {
				if ((m0.compareTo(m1) != 0) && intersects(m0, m1)) {
					return false;
				}
			}
		}
		return true;
	}

	protected abstract boolean intersects(Mapping m0, Mapping m1);

	public GitHubRepo normalize(RootCollectionRead rcr) {
		if (mappings != null) {
			mappings.forEach(mapping -> mapping.normalize(rcr));
		}
		return this;
	}

	@JsonIgnore
	protected static List<Ref> getPrevRefs(UUID uuid, String path, Set<String> indices) {
		List<Ref> refs = new ArrayList<>();
		int offset = 0;
		while (true) {
			int n = forEachRef(uuid, path, indices, offset, o -> refs.add(o));
			if (n == 0) {
				return refs;
			}
			offset += n;
		}
	}

	protected static int forEachRef(UUID uuid, String path, Set<String> indices, int offset, Consumer<Ref> consumer) {
		DbBase db = GitHubRepos.db();
		/*
		Map<String, String> kvs = Map.of(String.format("%s.%s", DbTaxiiRef.refKey, db.keyword(uuidKey)),
				uuid.toString());
		if (path != null) {
			kvs = new HashMap<>(kvs);
			kvs.put(String.format("%s.%s", DbTaxiiRef.refKey, db.keyword(Ref.pathKey)), path);
		}
		*/
		Map<String, String> kvs = Map.of(String.format("%s.%s", DbTaxiiRef.refKey, db.keyword(uuidKey)),
				uuid.toString());
		if (path != null) {
			kvs = new HashMap<>(kvs);
			kvs.put(String.format("%s.%s", DbTaxiiRef.refKey, db.keyword(Ref.pathKey)), path);
		}
		Map<String, Pair<Integer, Integer>> ranges = Map.of(String.format("%s.%s", DbTaxiiRef.refKey, Ref.offsetKey),
				Pair.of(offset, DbBase.maxSize));
		List<ObjectNode> chunk = db.searchWithRange(kvs, ranges, ObjectNode.class, DbBase.maxSize, indices);
		if ((chunk == null) || chunk.isEmpty()) {
			return 0;
		}
		for (ObjectNode object : chunk) {
			consumer.accept(JSON.convertValue(object.get(DbTaxiiRef.refKey), Ref.class));
		}
		return chunk.size();
	}

	public void setUuid(UUID uuid) {
		this.uuid = uuid;
	}

	public void setMappings(Set<Mapping> mappings) {
		this.mappings = ((mappings != null) && mappings.isEmpty()) ? null : mappings;
	}

}
