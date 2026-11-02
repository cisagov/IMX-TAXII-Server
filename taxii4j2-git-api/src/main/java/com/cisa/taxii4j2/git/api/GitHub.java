/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.api;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.auth.data.TAXIICredentials;
import com.cisa.taxii4j2.client.RemoteBase;
import com.cisa.taxii4j2.client.RemoteBearerBase;
import com.cisa.taxii4j2.git.api.Tree.Entry;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

public class GitHub implements AutoCloseable {

	protected static final String produces = "application/vnd.github+json";
	protected static final Logger logger = LogManager.getLogger(GitHub.class);

	private RemoteBase client;

	public RemoteBase getClient() {
		return client;
	}

	public static class Wrapper {

		protected static final String shaKey = "sha";
		protected static final String urlKey = "url";

		private final JsonNode object;

		public Wrapper(JsonNode object) {
			super();
			this.object = object;
		}

		public JsonNode getObject() {
			return object;
		}

		@Override
		public String toString() {
			return object.toPrettyString();
		}

		public String sha() {
			return object.get(shaKey).asText();
		}

		public String url() {
			return object.get(urlKey).asText();
		}

	}

	public static final URI baseUri = URI.create("https://api.github.com");
	public static final URI reposUri = UriBuilder.fromUri(baseUri).path("repos").build();

	public static URL repoUrl(String owner, String repo) throws MalformedURLException {
		return UriBuilder.fromUri(reposUri).path(owner).path(repo).build().toURL();
	}

	public GitHub(String owner, String repo, String token) throws MalformedURLException {
		this(repoUrl(owner, repo), token);
	}

	public GitHub(String _url, String token) throws MalformedURLException {
		this(new URL(_url), token);
	}

	public GitHub(URL url, String token) {
		super();
		client = (token != null) ? new RemoteBearerBase(new GHToken(token), url, null, produces, null)
				: new RemoteBase(url, null, produces, null);
	}

	protected void init(URL url, TAXIICredentials token) {
		client = (token != null) ? new RemoteBearerBase(token, url, null, produces, null)
				: new RemoteBase(url, null, produces, null);
	}

	private static class GHToken extends TAXIICredentials {

		private final String header;

		public GHToken(String token) {
			super();
			this.header = String.format("Bearer %s", token);
		}

		@Override
		public String getHeaderValue() {
			return header;
		}

	}

	public static TAXIICredentials token(String token) {
		return (token != null) ? new GHToken(token) : null;
	}

	public <T extends Wrapper> T get(Class<T> clazz, MultivaluedMap<String, String> queryParams, String... paths) {
		return get(client.paths(queryParams, paths), clazz);
	}

	private <T extends Wrapper> T get(Invocation.Builder builder, Class<T> clazz) {
		try {
			Response response = builder.get();
			return clazz.getConstructor(JsonNode.class).newInstance(response.readEntity(JsonNode.class));
		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			throw new BadRequestException(e);
		}
	}

	public <T extends Wrapper> T get(String url, Class<T> clazz) {
		return get(client.paths(client.target(url), null, produces, null), clazz);
	}

	public Response postHelper(Object entity, MultivaluedMap<String, String> qps, String... paths) {
		return client.postHelper(entity, qps, paths);
	}

	@Override
	public void close() throws Exception {
		client.close();
	}

	private static final String TOKEN_KEY = "GITHUB_TOKEN";

	@JsonInclude(Include.NON_NULL)
	public static class Info {

		private static final String includesKey = "includes";
		private static final String excludesKey = "excludes";
		private static final String ownerKey = "owner";
		private static final String repoKey = "repo";
		private static final String tokenKey = "token";
		private static final String linksKey = "links";

		@JsonProperty(ownerKey)
		private final String owner;

		@JsonProperty(repoKey)
		private final String repo;

		@JsonProperty(tokenKey)
		private final String token;

		@JsonProperty(includesKey)
		private final Set<String> includes;

		@JsonProperty(excludesKey)
		private final Set<String> excludes;

		@JsonProperty(linksKey)
		private final Map<String, String> links;

		@JsonCreator
		public Info(@JsonProperty(value = ownerKey, required = true) String owner,
				@JsonProperty(value = repoKey, required = true) String repo,
				@JsonProperty(value = tokenKey, required = false) String token,
				@JsonProperty(value = includesKey, required = true) Set<String> includes,
				@JsonProperty(value = excludesKey, required = false) Set<String> excludes,
				@JsonProperty(value = linksKey, required = false) Map<String, String> links) {
			super();
			this.owner = owner;
			this.repo = repo;
			this.token = (token != null) ? token : System.getenv(TOKEN_KEY);
			this.includes = new HashSet<>(includes);
			this.excludes = ((excludes != null) && !excludes.isEmpty()) ? new HashSet<>(excludes) : null;
			this.links = ((links != null) && !links.isEmpty()) ? new HashMap<>(links) : null;
		}

		public String getOwner() {
			return owner;
		}

		public String getRepo() {
			return repo;
		}

		public Set<String> getIncludes() {
			return includes;
		}

		public Set<String> getExcludes() {
			return excludes;
		}

		public String getToken() {
			return token;
		}

		public Map<String, String> getLinks() {
			return links;
		}

	}

	public static interface Handler {

		void delete(Path path) throws Exception;

		String getSha(Path path) throws Exception;

		void putSha(Path path, String sha) throws Exception;

		void accept(Path path, String content, String sha) throws Exception;

		void link(Path link, Path target) throws Exception;

	}

	public static void accept(Info info, Handler handler) throws Exception {
		Set<String> includes = info.getIncludes();
		if ((includes == null) || includes.isEmpty()) {
			return;
		}
		String repo = info.getRepo();
		try (GitHub gh = new GitHub(info.getOwner(), repo, info.getToken())) {
			Commit commit = gh.get(Commits.class, null, "commits").commit();
			Path path = Paths.get(repo);
			String prev = handler.getSha(path);
			String curr = commit.sha();
			if ((prev != null) && prev.equalsIgnoreCase(curr)) {
				return;
			}
			handler.delete(path);
			Set<String> excludes = info.getExcludes();
			if (excludes == null) {
				excludes = Collections.emptySet();
			}
			gh.accept(handler, gh.get(commit.treeUrl(), Tree.class), includes, excludes, path);
			handler.putSha(path, curr);
			Map<String, String> links = info.getLinks();
			if(links != null) {
				links.forEach((link, target) -> {
					try {
						handler.link(Paths.get(link), Paths.get(target));
					} catch(Exception e) {
						logger.warn(e.getMessage());
					}
				});
			}
		}
	}

	private void accept(Handler handler, Tree tree, Set<String> includes, Set<String> excludes, Path parentPath)
			throws Exception {
		for (Entry entry : tree.getEntries()) {

			if (!entry.isTree() && !entry.isBlob()) {
				continue;
			}

			Path childPath = parentPath.resolve(entry.getPath());

			if (excludes.contains(childPath.toString())) {
				continue;
			}

			boolean isIncluded = (includes == null) || includes.contains(childPath.toString());
			if (entry.isTree()) {
				String prev = handler.getSha(childPath);
				String curr = entry.sha();
				if ((prev != null) && prev.equalsIgnoreCase(curr)) {
					continue;
				}
				accept(handler, entry.getTree(this), isIncluded ? null : includes, excludes, childPath);
				handler.putSha(childPath, curr);
			} else if (isIncluded) {
				handler.accept(childPath, entry.getBlob(this).content(), entry.sha());
			}

		}
	}

}
