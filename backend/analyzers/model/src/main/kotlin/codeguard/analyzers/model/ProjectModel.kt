package codeguard.analyzers.model

import org.jetbrains.kotlin.psi.KtFile
import java.nio.file.Path

enum class SourceType { KOTLIN, KOTLIN_SCRIPT, YAML, PROPERTIES, SQL, LOCKFILE, TOML, MARKDOWN, ENV, XML, PEM, DOCKERFILE, JSON, OTHER, ADVISORY_DATABASE }

data class Location(val path: String, val line: Int, val endLine: Int? = null)

data class Located<T>(val value: T, val location: Location)

data class ParseError(val path: String, val line: Int?, val message: String)

class SourceFile(
    val path: String,
    val type: SourceType,
    val text: String,
    val sha256: String,
) {
    private val lineStarts = buildList {
        add(0)
        text.forEachIndexed { index, character ->
            if (character == '\n' || (character == '\r' && text.getOrNull(index + 1) != '\n')) {
                add(index + 1)
            }
        }
    }.toIntArray()

    fun lineAt(offset: Int): Int {
        require(offset in 0..text.length)
        val index = lineStarts.binarySearch(offset)
        return if (index >= 0) index + 1 else -index - 1
    }

    fun location(offset: Int): Location = Location(path, lineAt(offset))
}

enum class DeclarationKind { CLASS, FUNCTION, PROPERTY, CONSTANT }

data class Declaration(
    val name: String,
    val qualifiedName: String,
    val kind: DeclarationKind,
    val location: Location,
)

data class DeclarationIndex(val byName: Map<String, List<Declaration>>)

data class CallSite(val name: String, val location: Location, val target: Declaration?)

data class CallIndex(val byFile: Map<String, List<CallSite>>)

class ProjectModel internal constructor(
    val root: Path,
    val files: List<SourceFile>,
    val kotlin: Map<String, KtFile>,
    val declarations: DeclarationIndex,
    val calls: CallIndex,
    val config: List<ConfigEntry>,
    val gradle: GradleModel,
    val spring: SpringModel,
    val sqlSchema: SqlSchema,
    val parseErrors: List<ParseError>,
    /** Файлы проекта по языкам (по расширению). */
    val languages: List<LanguageUsage> = emptyList(),
    /** Каталоги, которые не обходились (node_modules, vendor, build, .git…). */
    val ignoredDirectories: List<String> = emptyList(),
)

enum class ModelStatus { COMPLETE, PARTIAL, FAILED }

/** Safe to publish in run metadata. The model is passed separately in-process. */
data class ModelSummary(val status: ModelStatus, val filesRead: Int, val parseErrors: Int)

class ProjectModelResult internal constructor(
    val model: ProjectModel?,
    val summary: ModelSummary,
)
