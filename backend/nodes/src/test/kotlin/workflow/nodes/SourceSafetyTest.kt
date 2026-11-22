package workflow.nodes

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import workflow.engine.NodeFailure
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.DosFileAttributeView
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SourceSafetyTest {
    @TempDir lateinit var root: Path

    @Test fun `archive path stays inside workspace`() {
        val archive = zip("src/Main.kt")
        val output = root.resolve("safe")
        SafeArchives.extract(archive, output)
        assertEquals("test", Files.readString(output.resolve("src/Main.kt")))
    }

    @Test fun `parent paths are rejected before files can escape`() {
        val archive = zip("../outside")
        assertThrows(IllegalArgumentException::class.java) { SafeArchives.extract(archive, root.resolve("project")) }
        assertFalse(Files.exists(root.resolve("outside")))
    }

    @Test fun `local and unlisted repository destinations are rejected`() {
        val sources = SourceNodes(root.toString()) { listOf("https://github.com/example-org/training") }
        for (input in listOf("file:///etc", "https://127.0.0.1/owner/example", "https://github.com/other/repo")) {
            assertThrows(InputRejected::class.java) { sources.validateRepository(input) }
        }
        assertThrows(IllegalArgumentException::class.java) { PublicNetwork.resolve("127.0.0.1") }
        assertThrows(IllegalArgumentException::class.java) { PublicNetwork.resolve("::1") }
    }

    @Test fun `repository fetch chooses HEAD branch or exact commit`() {
        val params = ObjectMapper().createObjectNode()
        val commit = "1".repeat(40)
        assertEquals("HEAD", repositoryRef(params, null))
        assertEquals("refs/heads/team/release-v2", repositoryRef(params.put("branch", "team/release-v2"), null))
        assertEquals(commit, repositoryRef(params, commit))
        assertThrows(NodeFailure::class.java) { repositoryRef(params.put("commitSha", commit), null) }
        params.remove("branch")
        assertEquals(commit, repositoryRef(params, null))
        params.remove("commitSha")
        assertThrows(NodeFailure::class.java) { repositoryRef(params.put("branch", "release..old"), null) }
    }

    @Test fun `scratch cleanup removes git pack files on Windows`() {
        val scratch = Files.createDirectory(root.resolve("git"))
        val pack = Files.writeString(scratch.resolve("objects.pack"), "scratch")
        if (System.getProperty("os.name").startsWith("Windows")) {
            Files.getFileAttributeView(pack, DosFileAttributeView::class.java).setReadOnly(true)
        }
        deleteTree(scratch)
        assertFalse(Files.exists(scratch))
    }

    @Test fun `project subdirectory remains within the snapshot`() {
        val snapshot = Files.createDirectory(root.resolve("snapshot"))
        val project = Files.createDirectory(snapshot.resolve("sample-project"))
        assertEquals(project.toRealPath(), snapshotDirectory(snapshot, "sample-project"))
        assertEquals(snapshot, snapshotDirectory(snapshot, ""))
        for (path in listOf("../snapshot", "sample-project/..", "/sample-project", "C:/sample-project", "a\\b")) {
            assertThrows(IllegalArgumentException::class.java) { snapshotDirectory(snapshot, path) }
        }
    }

    @Test fun `subdirectory snapshot inherits repository advisory without copying other files`() {
        for (prefix in listOf("", "training-main/")) {
            val snapshot = Files.createTempDirectory(root, "repository")
            val repository = snapshot.resolve(prefix)
            val catalogDir = Files.createDirectories(repository.resolve("vulnerability-database"))
            Files.writeString(catalogDir.resolve("vulnerabilities.json"), "repository catalog")
            Files.writeString(catalogDir.resolve("README.md"), "repository documentation")
            Files.writeString(repository.resolve("vulnerabilities.json"), "repository root catalog")
            val project = Files.createDirectories(repository.resolve("sample-project"))
            if (prefix.isEmpty()) Files.writeString(project.resolve("vulnerabilities.json"), "project catalog")

            val selected = snapshotDirectory(snapshot, prefix + "sample-project")
            assertEquals(project.toRealPath(), selected)
            assertEquals("repository catalog", Files.readString(selected.resolve("vulnerability-database/vulnerabilities.json")))
            val expected = if (prefix.isEmpty()) "project catalog" else "repository root catalog"
            assertEquals(expected, Files.readString(selected.resolve("vulnerabilities.json")))
            assertFalse(Files.exists(selected.resolve("vulnerability-database/README.md")))
        }
    }

    @Test fun `repository input is normalized to canonical url with optional branch and subdir`() {
        val canonical = "https://github.com/example-org/training"
        for (input in listOf(canonical, "$canonical/", "$canonical.git", "$canonical.git/", " $canonical ")) {
            assertEquals(RepositoryInput(canonical), normalizeRepositoryInput(input), input)
        }
        assertEquals(RepositoryInput(canonical, "main"), normalizeRepositoryInput("$canonical/tree/main"))
        assertEquals(RepositoryInput(canonical, "main", "sample-project/app"),
            normalizeRepositoryInput("$canonical/tree/main/sample-project/app/"))
        assertEquals(RepositoryInput("https://gitlab.com/team/demo"), normalizeRepositoryInput("https://gitlab.com/team/demo.git"))
        for (bad in listOf("http://github.com/a/b", "https://github.com/a", "https://github.com/a/b?x=1",
            "https://github.com/a/b/tree/main/../x", "https://github.com/a/b/issues", "file:///etc")) {
            assertNull(normalizeRepositoryInput(bad), bad)
        }
        val sources = SourceNodes(root.toString()) { listOf(canonical) }
        sources.validateRepository("$canonical.git/")
        sources.validateRepository("$canonical/tree/dev")
    }

    @Test fun `project root is detected as the shallowest gradle directory`() {
        val repo = Files.createDirectories(root.resolve("detect-one"))
        Files.createDirectories(repo.resolve("docs"))
        val project = Files.createDirectories(repo.resolve("sample-project"))
        Files.writeString(project.resolve("settings.gradle.kts"), "")
        Files.createDirectories(project.resolve("app")).resolve("build.gradle.kts").let { Files.writeString(it, "") }
        val resolved = resolveProject(repo, "")
        assertEquals("sample-project", resolved.subdir)
        assertEquals(project.toRealPath(), resolved.path)
        // Заданная несуществующая папка тоже определяется автоматически.
        assertEquals("sample-project", resolveProject(repo, "missing").subdir)
        // Существующая заданная папка не переопределяется.
        assertEquals("docs", resolveProject(repo, "docs").subdir)
    }

    @Test fun `project at repository root and legacy repository without gradle files`() {
        val rooted = Files.createDirectories(root.resolve("detect-root"))
        Files.writeString(rooted.resolve("build.gradle.kts"), "")
        Files.createDirectories(rooted.resolve("nested")).resolve("settings.gradle.kts").let { Files.writeString(it, "") }
        assertEquals("", resolveProject(rooted, "").subdir)
        val plain = Files.createDirectories(root.resolve("detect-plain"))
        Files.writeString(plain.resolve("README.md"), "x")
        assertEquals("", resolveProject(plain, "").subdir)
        assertThrows(NodeFailure::class.java) { resolveProject(plain, "missing") }
    }

    @Test fun `ambiguous project roots fail with a list of candidates`() {
        val repo = Files.createDirectories(root.resolve("detect-many"))
        for (name in listOf("alpha", "beta")) {
            Files.writeString(Files.createDirectories(repo.resolve(name)).resolve("settings.gradle.kts"), "")
        }
        val error = assertThrows(NodeFailure::class.java) { resolveProject(repo, "") }
        assertTrue("alpha" in error.message.orEmpty() && "beta" in error.message.orEmpty(), error.message)
        val wrong = assertThrows(NodeFailure::class.java) { resolveProject(repo, "gamma") }
        assertTrue("gamma" in wrong.message.orEmpty() && "alpha" in wrong.message.orEmpty(), wrong.message)
    }

    private fun zip(path: String): Path =root.resolve("archive.zip").also { archive ->
        ZipOutputStream(Files.newOutputStream(archive)).use { zip ->
            zip.putNextEntry(ZipEntry(path))
            zip.write("test".toByteArray())
            zip.closeEntry()
        }
    }
}
