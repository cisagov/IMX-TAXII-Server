/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.archive.DirImporter;
import com.cisa.taxii4j2.git.api.ApiLoadableRef;
import com.cisa.taxii4j2.git.api.Commit;
import com.cisa.taxii4j2.git.api.Commits;
import com.cisa.taxii4j2.git.api.FileLoadableRef;
import com.cisa.taxii4j2.git.api.GitHub;
import com.cisa.taxii4j2.git.api.OverrideLoadableRef;
import com.cisa.taxii4j2.git.api.Tree;
import com.cisa.taxii4j2.servlet.Dirs;

public class GitHubRepoApi extends GitHubRepo {

	private static final String urlKey = "url";
	private static final String tokenKey = "token";

	@JsonProperty(urlKey)
	private final String url;

	@JsonProperty(tokenKey)
	private final String token;

	public String getUrl() {
		return url;
	}

	public String getToken() {
		return token;
	}

	@JsonIgnore
	private final GitHub client;

	private static final String TOKEN_KEY = "GITHUB_TOKEN";

	public GitHubRepoApi(JsonNode root) {
		super(root);
		url = root.get(urlKey).asText();
		JsonNode _token = root.get(tokenKey);
		token = (_token != null) ? _token.asText() : System.getenv(TOKEN_KEY);
		try {
			client = new GitHub(url, token);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private String update(Commit commit, Mapping filter) {
		switch (filter.getType()) {
		case OBJECT:
			return update(commit, filter, GitHubRepos.dbTaxii().allObjectIndices());
		case SCHEMA:
			return update(commit, filter, Collections.singleton(GitHubRepos.schemaIndex()));
		default:
			throw new IllegalArgumentException();
		}
	}

	private String update(Commit commit, Mapping filter, Set<String> indices) {

		List<Ref> prevRefs = getPrevRefs(filter.getUuid(), null, indices);
		if (prevRefs == null) {
			prevRefs = Collections.emptyList();
		}
		Map<String, List<Ref>> removes = prevRefs.stream().collect(Collectors.groupingBy(r -> r.getPath()));
		List<LoadableRef> creates = getLoadables(commit, filter);

		Iterator<LoadableRef> iCreate = creates.iterator();
		while (iCreate.hasNext()) {
			LoadableRef create = iCreate.next();
			String cPath = create.getPath();
			List<Ref> refs = removes.get(cPath);
			if ((refs == null) || refs.isEmpty()) {
				/*
				 * previously unseen, create it...
				 */
				continue;
			}
			String rSha = refs.get(0).getSha();
			if (rSha == null) {
				/*
				 * previous has no SHA, replace it...
				 */
				continue;
			}
			/*
			 * previous has SHA...
			 */
			String cSha = create.getSha();
			if ((cSha == null) || cSha.equalsIgnoreCase(rSha)) {
				/*
				 * current no SHA or same as previous, ignore...
				 */
				iCreate.remove();
				removes.remove(cPath);
			}
		}

		/*
		 * ok...remove orphaned and changed refs / objects...
		 */
		String[] paths = removes.values().stream().map(rs -> rs.stream()).flatMap(s -> s).map(r -> r.getPath())
				.toArray(String[]::new);
		logger.info(String.format("GitHubRepo.update: removing [\n%s\n]", String.join("\n", paths)));
		removes.values().forEach(rs -> rs.forEach(r -> r.delete()));

		/*
		 * ...and insert new refs / objects
		 */
		logger.info(String.format("GitHubRepo.update: creating [\n%s\n]",
				String.join("\n", creates.stream().map(r -> r.getPath()).toArray(String[]::new))));
		creates.forEach(ref -> ref.create(client.getClient(), filter));

		return (commit != null) ? commit.sha() : null;
	}

	private List<LoadableRef> getLoadables(Mapping filter) {
		UUID uuid = filter.getUuid();
		FilterType type = filter.getType();
		try {
			Path src = Dirs.instance().boostrap().resolve("mirror").resolve(String.format("%s.tgz", uuid));
			Path dst = Files.createTempDirectory(uuid.toString());
			DirImporter.factory(src, dst);
			List<LoadableRef> refs = new ArrayList<>();
			Files.walkFileTree(dst, new SimpleFileVisitor<Path>() {

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					refs.add(new FileLoadableRef(uuid, dst.relativize(file).toString(), type, file));
					return FileVisitResult.CONTINUE;
				}

			});
			return refs;
		} catch (Exception e) {
			logger.warn(String.format("GitHubRepoApi.getLoadables: can't bootstrap %s", uuid));
			return Collections.emptyList();
		}
	}

	private List<LoadableRef> getLoadables(Commit commit, Mapping filter) {

		if (commit == null) {
			return getLoadables(filter);
		}

		List<LoadableRef> refs = new ArrayList<>();

		for (String include : filter.getIncludes()) {

			Path path = Paths.get(include);

			Tree branch = client.get(commit.treeUrl(), Tree.class);
			Tree.Entry blob = null;

			Iterator<Path> iPath = path.iterator();
			while (iPath.hasNext()) {
				String name = iPath.next().toString();
				Tree.Entry entry = branch.getEntry(name);
				if (entry == null) {
					throw new IllegalArgumentException(
							String.format("GitHub.gitBlobUrls: unknown name %s in %s", name, path));
				}
				if (entry.isTree()) {
					branch = entry.getTree(client);
				} else if (entry.isBlob()) {
					if (iPath.hasNext()) {
						throw new IllegalArgumentException(
								String.format("GitHub.gitBlobUrls: %s in %s was premature blob", name, path));
					}
					branch = null;
					blob = entry;
					break;
				}
			}

			if (blob != null) {
				refs.add(new ApiLoadableRef(filter.getUuid(), path.toString(), blob.sha(), blob.url(),
						filter.getType()));
			} else if (branch != null) {
				for (Tree.Entry entry : branch.getEntries()) {
					getBlobRefs(filter.getUuid(), filter.getType(), entry, path, filter.getExcludes(), refs);
				}
			} else {
				throw new IllegalStateException(
						"GitHub.getBlobUrls: should have had either a blob or tree at this point...");
			}

		}

		if (filter.getOverrides() != null) {
			for (String override: filter.getOverrides()) {
				refs.add(new OverrideLoadableRef(filter.getUuid(), override, filter.getType()));
			}
		}
		return refs;
	}

	private void getBlobRefs(UUID uuid, FilterType type, Tree.Entry parent, Path parentPath, Set<String> excludes,
			List<LoadableRef> refs) {
		Path path = parentPath.resolve(parent.getPath());
		if ((excludes != null) && excludes.contains(path.toString())) {
			return;
		}
		if (parent.isBlob()) {
			refs.add(new ApiLoadableRef(uuid, path.toString(), parent.sha(), parent.url(), type));
		} else if (parent.isTree()) {
			for (Tree.Entry entry : parent.getTree(client).getEntries()) {
				getBlobRefs(uuid, type, entry, path, excludes, refs);
			}
		} else {
			throw new IllegalStateException(String.format("GitHub.getBlobUrls: unknown type %s", parent.getType()));
		}
	}

	@Override
	protected void create(Mapping mapping) {
		Commit commit = null;
		try {
			commit = client.get(Commit.class, null, "commits", getSha());
		} catch (Exception e) {
			// can't connect?
			logger.warn("Unable to connect to github repository", e);
			return;
		}
		update(commit, mapping);
	}

	private static class IConsumer implements Consumer<Ref> {

		private boolean intersects = false;
		private final Mapping m1;

		public IConsumer(Mapping m1) {
			super();
			this.m1 = m1;
		}

		@Override
		public void accept(Ref t) {
			if (!intersects) {
				intersects = m1.isIncluded(t.getPath());
			}
		}

	}

	@Override
	protected boolean intersects(Mapping m0, Mapping m1) {
		if (m0.compareTo(m1) == 0) {
			return true;
		}
		UUID uuid = m0.getUuid();
		Set<String> indices = indices(m0);
		int offset = 0;
		IConsumer c = new IConsumer(m1);
		while (!c.intersects) {
			int n = forEachRef(uuid, null, indices, offset, c);
			if (n == 0) {
				break;
			}
			offset += n;
		}
		return c.intersects;
	}

	@Override
	public void update(Mapping mapping) {
		Commit commit = null;
		try {
			commit = client.get(Commit.class, null, "commits", getSha());
		} catch (Exception e) {
			// can't connect?
			logger.warn("Unable to connect to github repository", e);
		}
		update(commit, mapping);
	}

	@Override
	public boolean hasChanged() {
		String prev = getSha();
		Commit commit = null;
		try {
			commit = client.get(Commits.class, null, "commits").commit();
		} catch (Exception e) {
			// can't connect?
			logger.warn("Unable to connect to github repository", e);
			// Leave whatever we have already downloaded in place.
			return false;
		}
		if (commit == null) {
			return true;
		}
		String curr = commit.sha();
		if ((prev == null) || !prev.equalsIgnoreCase(curr)) {
			setSha(curr);
			return true;
		}
		return false;
	}

	@Override
	public void update() {
		// NOP - everything is done in update(Mapping)...
	}

}
