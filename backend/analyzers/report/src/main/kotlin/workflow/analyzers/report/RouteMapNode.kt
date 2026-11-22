package workflow.analyzers.report

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import codeguard.analyzers.model.DataAccessMethod
import codeguard.analyzers.model.Endpoint
import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SecurityRule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtStringTemplateEntryWithExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType
import org.springframework.stereotype.Component
import workflow.analyzers.CoverageRule
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import java.util.ArrayDeque

@Component
class RouteMapNode : NodeDefinition {
    override val type = "output.route-map"
    override val title = "Карта маршрутов"
    override val category = NodeCategory.OUTPUT
    override val inputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val outputs = listOf(PortSpec("report", PortType.REPORT))
    override val paramsSchema = JsonNodeFactory.instance.objectNode()
        .put("type", "object").put("additionalProperties", false)

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val model = input.ports["model"] as? ProjectModel
            ?: return@withContext NodeOutput(emptyMap(), NodeStatus.FAILED)
        NodeOutput(mapOf("report" to routeMap(model)), coverage = routeMapCoverage(model))
    }
}

private val routeMapRules = listOf(
    CoverageRule(
        "route-map.spring-access-policy",
        "Первое применимое правило Spring-доступа",
        "Сопоставляет HTTP-метод и сегменты маршрута с правилами Spring в порядке объявления. Неоднозначное сопоставление помечает в карте как неустановленное.",
    ),
    CoverageRule(
        "route-map.data-access-path",
        "Путь от маршрута к доступу к данным",
        "Обходит разрешимые Kotlin-вызовы от endpoint до методов доступа к данным и перечисляет найденные таблицы; динамические или неоднозначные вызовы не считаются доказанными.",
    ),
    CoverageRule(
        "route-map.owner-columns",
        "Колонки владельца в схеме",
        "Для найденных таблиц сопоставляет распознанную схему и owner-колонки из SQL, Liquibase или JPA. Неустановленная схема отмечается отдельно.",
    ),
)

internal fun routeMapCoverage(model: ProjectModel): Map<String, Any> {
    val skipped = model.parseErrors.map { error ->
        buildMap<String, Any> {
            put("path", error.path)
            put("reason", "Ошибка чтения или разбора входного файла")
            error.line?.let { put("line", it) }
        }
    }
    val skippedPaths = model.parseErrors.map { it.path }.toSet()
    val applied = routeMapRules.takeIf { model.spring.endpoints.isNotEmpty() }.orEmpty()
    return mapOf(
        "status" to if (model.parseErrors.isEmpty()) "COMPLETE" else "PARTIAL",
        "filesAnalyzed" to model.files.count { it.path !in skippedPaths },
        "filesSkipped" to skipped,
        "rulesApplied" to applied.map(CoverageRule::id),
        "rules" to applied,
        "unresolved" to emptyList<Any>(),
        "dismissed" to emptyList<Any>(),
    )
}

internal fun routeMap(model: ProjectModel): ObjectNode {
    val status = if (model.parseErrors.isEmpty()) "COMPLETE" else "PARTIAL"
    val artifact = JsonNodeFactory.instance.objectNode().put("kind", "route-map").put("status", status)
    val rows = artifact.putArray("routes")
    val tableIndex = RouteTableIndex(model)
    val endpoints = model.spring.endpoints.sortedWith(compareBy(Endpoint::path, Endpoint::method,
        Endpoint::function, { it.location.path }, { it.location.line }))
    for (endpoint in endpoints) {
        val policy = routePolicy(model.spring, endpoint)
        val row = rows.addObject()
            .put("function", endpoint.function)
            .put("accessStatus", policy.status)
        endpoint.method?.let { row.put("method", it) }
        endpoint.path?.let { row.put("path", it) }
        row.putObject("location").writeLocation(endpoint.location)
        policy.rule?.let { row.putObject("rule").writeRule(it) }
        val subsequent = row.putArray("subsequentRules")
        policy.subsequent.forEach { subsequent.addObject().writeRule(it) }
        val methodGuards = row.putArray("methodGuards")
        endpoint.securityAnnotations.forEach { guard ->
            methodGuards.addObject().put("name", guard.name).writeLocation(guard.location)
        }
        val tables = row.putArray("tables")
        val touched = tableIndex.tables(endpoint)
        row.put("tableEvidence", if (touched == null) "unresolved" else "located")
        for (name in touched.orEmpty()) {
            val table = tables.addObject().put("name", name)
            val columns = table.putArray("ownerColumns")
            val schema = model.sqlSchema.tables[name] ?: model.sqlSchema.tables.values.singleOrNull {
                it.name.equals(name, ignoreCase = true)
            }
            table.put("schemaKnown", schema != null)
            schema?.ownerColumns?.sorted()?.forEach { columns.add(it) }
        }
    }
    artifact.put("markdown", routeMarkdown(status, rows))
    return artifact
}

private fun routeMarkdown(status: String, rows: JsonNode) = buildString {
    appendLine("# Карта маршрутов")
    appendLine()
    appendLine("Покрытие модели: $status.")
    appendLine("Доступ отражает декларации Spring. Для неразрешённых правил требуется проверка.")
    appendLine()
    appendLine("| Метод | Маршрут | Первое правило | Последующие правила | Таблицы и колонки владельцев |")
    appendLine("| --- | --- | --- | --- | --- |")
    for (row in rows) {
        val later = row.path("subsequentRules").joinToString(", ", transform = ::describeRule).ifEmpty { "—" }
        val tables = row.path("tables").joinToString(", ") { table ->
            val columns = table.path("ownerColumns").joinToString(", ") { it.asText() }
            table.path("name").asText() + if (columns.isNotEmpty()) " ($columns)" else ""
        }.ifEmpty {
            if (row.path("tableEvidence").asText() == "located") "не используются" else "не установлено"
        }
        val rule = row.path("rule").takeIf(JsonNode::isObject)?.let(::describeRule) ?: "требует проверки"
        val cells = listOf(row.path("method").asText("любой"), row.path("path").asText("не установлен"), rule, later, tables)
        appendLine(cells.joinToString(" | ", "| ", " | ", transform = ::tableCell))
    }
}

private fun describeRule(rule: JsonNode): String =
    rule.path("accessText").asText() + " (" + rule.path("file").asText() + ":" + rule.path("line").asInt() + ")"

private class RouteTableIndex(private val model: ProjectModel) {
    private data class Function(
        val name: String,
        val path: String,
        val firstLine: Int,
        val lastLine: Int,
        val declaration: KtNamedFunction,
    )

    private val functions = model.files.flatMap { source ->
        model.kotlin[source.path]?.collectDescendantsOfType<KtNamedFunction>().orEmpty().mapNotNull { function ->
            val name = function.fqName?.asString() ?: return@mapNotNull null
            val first = source.lineAt(function.textRange.startOffset)
            val last = source.lineAt((function.textRange.endOffset - 1).coerceAtLeast(function.textRange.startOffset))
            Function(name, source.path, first, last, function)
        }
    }.groupBy(Function::name)
    private val sites = model.spring.repositories.groupBy(DataAccessMethod::function)

    fun tables(endpoint: Endpoint): List<String>? {
        val entry = functions[endpoint.function].orEmpty().singleOrNull { it.contains(endpoint.location) }
            ?: return null
        val visited = hashSetOf(entry)
        val pending = ArrayDeque<Function>().apply { add(entry) }
        val tables = sortedSetOf<String>()
        while (pending.isNotEmpty()) {
            val function = pending.removeFirst()
            sites[function.name].orEmpty().filter { function.contains(it.location) }.flatMapTo(tables) { it.tables }
            for (call in model.calls.byFile[function.path].orEmpty()) {
                if (!function.contains(call.location)) continue
                val target = call.target ?: continue
                val callable = functions[target.qualifiedName].orEmpty().singleOrNull { it.contains(target.location) }
                    ?: continue
                if (visited.add(callable)) pending.add(callable)
            }
        }
        return tables.toList().takeIf { it.isNotEmpty() || returnsOnlyConstants(entry) }
    }

    private fun returnsOnlyConstants(entry: Function): Boolean {
        val function = entry.declaration
        if (model.parseErrors.any { it.path == entry.path } || function.valueParameters.isNotEmpty()) return false
        val body = function.bodyExpression ?: return false
        if (body.isLiteral()) return true
        val call = body as? KtCallExpression ?: return false
        val factory = call.calleeExpression?.text?.takeIf { it == "listOf" || it == "emptyList" } ?: return false
        if (factory == "emptyList" && call.valueArguments.isNotEmpty()) return false
        if (call.lambdaArguments.isNotEmpty() || call.valueArguments.any { it.getArgumentExpression()?.isLiteral() != true }) {
            return false
        }
        val owner = function.parent.parent as? KtClassOrObject ?: return false
        if (owner.superTypeListEntries.isNotEmpty() || owner.primaryConstructorParameters.any { it.name == factory }) {
            return false
        }
        // The call index cannot resolve stdlib helpers. Exclude visible project/import shadowing before accepting one.
        return model.declarations.byName[factory].isNullOrEmpty() && function.containingKtFile.importDirectives.none { directive ->
            val imported = directive.importedFqName ?: return@none true
            if (directive.isAllUnder) imported.asString() != "kotlin.collections"
            else (directive.aliasName ?: imported.shortName().asString()) == factory &&
                imported.asString() != "kotlin.collections.$factory"
        }
    }

    private fun Function.contains(location: Location) =
        path == location.path && location.line in firstLine..lastLine
}

private fun KtExpression.isLiteral(): Boolean = when (this) {
    is KtConstantExpression -> true
    is KtStringTemplateExpression -> entries.none { it is KtStringTemplateEntryWithExpression }
    else -> false
}

private fun ObjectNode.writeLocation(location: Location) {
    put("file", location.path)
    put("line", location.line)
}

private fun ObjectNode.writeRule(rule: SecurityRule) {
    put("access", rule.access)
    put("accessText", rule.accessText ?: "${rule.access}()")
    put("matcher", rule.matcher)
    writeLocation(rule.location)
}

private fun tableCell(value: String): String = buildString {
    for (character in value) {
        when (character) {
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '&' -> append("&amp;")
            '|', '\\', '[', ']', '\u0060', '*', '_' -> append('\\').append(character)
            else -> append(if (character.isISOControl()) ' ' else character)
        }
    }
}
