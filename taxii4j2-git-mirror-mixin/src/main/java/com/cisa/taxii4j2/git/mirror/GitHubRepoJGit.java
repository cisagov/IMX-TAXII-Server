/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

public class GitHubRepoJGit extends GitHubRepo {

	static final String pathKey = "path";

	@JsonProperty(pathKey)
	private final String path;

	@JsonIgnore
	private final Path pathObj;

	public String getPath() {
		return path;
	}

	public GitHubRepoJGit(JsonNode root) {
		super(root);
		this.path = root.get(pathKey).asText();
		pathObj = Paths.get(path);
	}

	private static final String sha = "";

	@Override
	protected void create(Mapping mapping) {
		Map<Mapping, List<LoadableRef>> creates = new TreeMap<>();
		try (Git git = Git.open(pathObj.toFile())) {
			Set<String> _excludes = mapping.getExcludes();
			Set<String> excludes = (_excludes != null) ? _excludes : Collections.emptySet();
			for (String include : mapping.getIncludes()) {
				try {
					Files.walkFileTree(pathObj.resolve(include), new SimpleFileVisitor<Path>() {

						@Override
						public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
								throws IOException {
							return excludes.contains(pathObj.relativize(dir).toString()) ? FileVisitResult.SKIP_SUBTREE
									: FileVisitResult.CONTINUE;
						}

						@Override
						public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
							String ghPath = pathObj.relativize(file).toString();
							if (!excludes.contains(ghPath)) {
								creates.computeIfAbsent(mapping, m -> new ArrayList<>()).add(new LoadableRef(
										mapping.getUuid(), ghPath, sha, file.toUri().toString(), mapping.getType()));
							}
							return FileVisitResult.CONTINUE;
						}

					});
				} catch (Exception e) {
					throw new IllegalArgumentException(e);
				}
			}
		} catch (IOException e1) {
			throw new IllegalArgumentException(e1);
		}

		logger.info(String.format("GitHubRepo.update: creating [\n%s\n]", String.join("\n", creates.values()
				.stream().map(rs -> rs.stream()).flatMap(s -> s).map(r -> r.getPath()).toArray(String[]::new))));
		creates.forEach((m, rs) -> rs.forEach(r -> r.create(null, m)));

	}

	private static final int timeout = 5 * 60;

	@Override
	public void update() {
		try (Git git = Git.open(pathObj.toFile())) {

			logger.info(String.format("update: fetching %s...", path));
			git.fetch().setTimeout(timeout).call();
			logger.info("...update: fetch complete");

			List<DiffEntry> entries = null;
			Repository repository = git.getRepository();
			ObjectId from = repository.resolve("HEAD^{tree}");
			ObjectId to = repository.resolve(String.format("%s^{tree}", getMaster()));
			try (ObjectReader reader = repository.newObjectReader()) {
				CanonicalTreeParser iFrom = new CanonicalTreeParser();
				iFrom.reset(reader, from);
				CanonicalTreeParser iTo = new CanonicalTreeParser();
				iTo.reset(reader, to);
				entries = git.diff().setNewTree(iTo).setOldTree(iFrom).call();
			}

			logger.info(String.format("update: pulling %s...", path));
			git.pull().setTimeout(timeout).call();
			logger.info("...update: pull complete");

			List<Ref> refs = new ArrayList<>();
			Map<Mapping, List<LoadableRef>> loadableRefs = new TreeMap<>();
			for (DiffEntry entry : entries) {
				String path = entry.getOldPath();
				Mapping oldMapping = findMapping(path);
				List<Ref> prevRefs = (oldMapping != null) ? getPrevRefs(oldMapping.getUuid(), path, indices(oldMapping))
						: null;
				path = entry.getNewPath();
				Mapping newMapping = findMapping(path);
				LoadableRef loadableRef = (newMapping != null)
						? new LoadableRef(newMapping.getUuid(), path, sha, pathObj.resolve(path).toUri().toString(),
								newMapping.getType())
						: null;
				switch (entry.getChangeType()) {
				case ADD:
				case COPY:
					if (loadableRef != null) {
						loadableRefs.computeIfAbsent(newMapping, m -> new ArrayList<>()).add(loadableRef);
					}
					break;
				case DELETE:
					if (prevRefs != null) {
						refs.addAll(prevRefs);
					}
					break;
				case MODIFY:
				case RENAME:
					if (prevRefs != null) {
						refs.addAll(prevRefs);
					}
					if (loadableRef != null) {
						loadableRefs.computeIfAbsent(newMapping, m -> new ArrayList<>()).add(loadableRef);
					}
					break;
				default:
					break;
				}
			}

			logger.info(String.format("GitHubRepo.update: removing [\n%s\n]",
					String.join("\n", refs.stream().map(r -> r.getPath()).toArray(String[]::new))));
			refs.forEach(ref -> ref.delete());

			logger.info(String.format("GitHubRepo.update: creating [\n%s\n]", String.join("\n", loadableRefs.values()
					.stream().map(rs -> rs.stream()).flatMap(s -> s).map(r -> r.getPath()).toArray(String[]::new))));
			loadableRefs.forEach((m, rs) -> rs.forEach(r -> r.create(null, m)));

		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	private class IVisitor extends SimpleFileVisitor<Path> {

		private boolean intersects = false;
		private final Set<String> excludes;
		private final Mapping m1;

		public IVisitor(Set<String> excludes, Mapping m1) {
			super();
			this.excludes = excludes;
			this.m1 = m1;
		}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
			String ghPath = pathObj.relativize(dir).toString();
			if (excludes.contains(ghPath)) {
				return FileVisitResult.SKIP_SUBTREE;
			}
			intersects = m1.isIncluded(ghPath);
			return intersects ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
		}

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
			String ghPath = pathObj.relativize(file).toString();
			if (!excludes.contains(ghPath)) {
				intersects = m1.isIncluded(ghPath);
			}
			return intersects ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
		}

	};

	@Override
	protected boolean intersects(Mapping m0, Mapping m1) {
		if (m0.compareTo(m1) == 0) {
			return true;
		}
		try (Git git = Git.open(pathObj.toFile())) {
			Set<String> _excludes = m0.getExcludes();
			Set<String> excludes = (_excludes != null) ? _excludes : Collections.emptySet();
			IVisitor visitor = new IVisitor(excludes, m1);
			for (String include : m0.getIncludes()) {
				try {
					Files.walkFileTree(pathObj.resolve(include), visitor);
				} catch (Exception e) {
					throw new IllegalArgumentException(e);
				}
				if (visitor.intersects) {
					return true;
				}
			}
		} catch (IOException e1) {
			throw new IllegalArgumentException(e1);
		}
		return false;
	}

	@Override
	public void update(Mapping mapping) {
		// NOP - everything is done in update()
	}

	@Override
	public boolean hasChanged() {
		// always force update...
		return true;
	}

}
