package codeguard.analyzers.model

import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import java.io.StringReader
import java.util.Locale
import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLStreamConstants
import javax.xml.stream.XMLStreamException

data class SqlSchema(val tables: Map<String, Table>)

data class Table(
    val name: String,
    val columns: Map<String, Column>,
    val ownerColumns: Set<String>,
    val locations: List<Location>,
)

data class Column(val name: String, val location: Location)

internal fun parseSqlSchema(
    files: List<SourceFile>,
    kotlin: Map<String, KtFile>,
    errors: MutableList<ParseError>,
): SqlSchema {
    val schema = SchemaBuilder()
    val sqlFiles = files.filter {
        it.type == SourceType.SQL && (it.path.substringAfterLast('/').equals("schema.sql", true) || isFlywayMigration(it))
    }
    for (file in sqlFiles.sortedWith(::compareSqlFiles)) parseSqlFile(file, schema, errors)

    for (file in files) {
        when {
            file.type == SourceType.YAML && "databaseChangeLog" in file.text ->
                readYamlDocuments(file, errors) { parseLiquibaseYaml(file, it, schema) }
            file.type == SourceType.XML && "databaseChangeLog" in file.text -> parseLiquibaseXml(file, schema, errors)
            file.path in kotlin -> parseJpa(file, kotlin.getValue(file.path), schema)
        }
    }
    return schema.build()
}

private data class TableDefinition(
    val columns: MutableMap<String, Column> = linkedMapOf(),
    val ownerColumns: MutableSet<String> = linkedSetOf(),
    val locations: MutableSet<Location> = linkedSetOf(),
)

private class SchemaBuilder {
    private val tables = linkedMapOf<String, TableDefinition>()

    fun define(table: String, location: Location) {
        tables.getOrPut(table, ::TableDefinition).locations.add(location)
    }

    fun column(table: String, name: String, location: Location, owner: Boolean = false) {
        val definition = tables.getOrPut(table, ::TableDefinition)
        definition.columns.putIfAbsent(name, Column(name, location))
        if (owner || isOwnerName(name)) definition.ownerColumns.add(name)
    }

    fun dropTable(table: String) {
        tables.remove(table)
    }

    fun dropColumn(table: String, name: String) {
        tables[table]?.columns?.remove(name)
        tables[table]?.ownerColumns?.remove(name)
    }

    fun build(): SqlSchema = SqlSchema(tables.mapValues { (name, definition) ->
        Table(name, definition.columns.toMap(), definition.ownerColumns.toSet(), definition.locations.toList())
    })
}

private val ownerNames = setOf(
    "owner", "customer", "user", "owner_id", "customer_id", "user_id", "ownerid", "customerid", "userid",
)
private val camelBoundary = Regex("([a-z0-9])([A-Z])")

private fun normalName(name: String): String = name.lowercase(Locale.ROOT)

private fun snakeName(name: String): String = normalName(
    camelBoundary.replace(name) { match -> "${match.groupValues[1]}_${match.groupValues[2]}" },
)

private fun isOwnerName(name: String): Boolean = snakeName(name) in ownerNames

private val flywayName = Regex("""V([0-9]+(?:[._][0-9]+)*)__.+[.]sql""", RegexOption.IGNORE_CASE)
private val flywayRepeatableName = Regex("""R__.+[.]sql""", RegexOption.IGNORE_CASE)

private fun isFlywayMigration(file: SourceFile): Boolean {
    val name = file.path.substringAfterLast('/')
    return "/db/migration/" in "/${file.path}" && (flywayName.matches(name) || flywayRepeatableName.matches(name))
}

private fun compareSqlFiles(first: SourceFile, second: SourceFile): Int {
    val firstName = first.path.substringAfterLast('/')
    val secondName = second.path.substringAfterLast('/')
    val firstVersion = flywayName.matchEntire(firstName)
    val secondVersion = flywayName.matchEntire(secondName)
    val firstGroup = if (firstVersion != null) 1 else if (flywayRepeatableName.matches(firstName)) 2 else 0
    val secondGroup = if (secondVersion != null) 1 else if (flywayRepeatableName.matches(secondName)) 2 else 0
    if (firstGroup != secondGroup) return firstGroup.compareTo(secondGroup)
    if (firstVersion != null && secondVersion != null) {
        val left = firstVersion.groupValues[1].split('.', '_')
        val right = secondVersion.groupValues[1].split('.', '_')
        for (index in 0 until maxOf(left.size, right.size)) {
            val a = left.getOrElse(index) { "0" }.trimStart('0')
            val b = right.getOrElse(index) { "0" }.trimStart('0')
            if (a.length != b.length) return a.length.compareTo(b.length)
            if (a != b) return a.compareTo(b)
        }
    }
    return first.path.compareTo(second.path)
}

private enum class SqlTokenKind { WORD, IDENTIFIER, SYMBOL, VALUE }

private data class SqlToken(val text: String, val offset: Int, val kind: SqlTokenKind) {
    fun keyword(word: String): Boolean = kind == SqlTokenKind.WORD && text.equals(word, ignoreCase = true)
    fun symbol(character: String): Boolean = kind == SqlTokenKind.SYMBOL && text == character
    fun identifier(): String? = text.takeIf { kind == SqlTokenKind.WORD || kind == SqlTokenKind.IDENTIFIER }
}

private class InvalidSql(val offset: Int) : RuntimeException()

private val dollarQuote = Regex("""\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$""")

/** Reads lexical SQL syntax only. Literal and procedural bodies cannot become declarations. */
private fun sqlTokens(sql: String): Sequence<SqlToken> = sequence {
    var index = 0
    while (index < sql.length) {
        val start = index
        val character = sql[index]
        when {
            character.isWhitespace() || character == '\uFEFF' -> index++
            sql.startsWith("--", index) -> {
                index += 2
                while (index < sql.length && sql[index] != '\n' && sql[index] != '\r') index++
            }
            sql.startsWith("/*", index) -> {
                var depth = 1
                index += 2
                while (index < sql.length && depth > 0) {
                    when {
                        sql.startsWith("/*", index) -> { depth++; index += 2 }
                        sql.startsWith("*/", index) -> { depth--; index += 2 }
                        else -> index++
                    }
                }
                if (depth != 0) throw InvalidSql(start)
            }
            character == '$' -> {
                val delimiter = dollarQuote.matchAt(sql, index)?.value
                if (delimiter == null) {
                    yield(SqlToken("$", index++, SqlTokenKind.SYMBOL))
                } else {
                    val end = sql.indexOf(delimiter, index + delimiter.length)
                    if (end == -1) throw InvalidSql(start)
                    index = end + delimiter.length
                    yield(SqlToken("", start, SqlTokenKind.VALUE))
                }
            }
            character == '\'' || character == '"' || character == '`' || character == '[' -> {
                val closing = if (character == '[') ']' else character
                val value = StringBuilder()
                val escapedString = character == '\'' && sql.getOrNull(index - 1)?.equals('e', true) == true &&
                    (index < 2 || !sql[index - 2].isLetterOrDigit())
                index++
                var closed = false
                while (index < sql.length) {
                    val next = sql[index++]
                    if (escapedString && next == '\\') {
                        if (index < sql.length) index++
                    } else if (next == closing) {
                        if (sql.getOrNull(index) != closing) {
                            closed = true
                            break
                        }
                        index++
                        if (character != '\'') value.append(next)
                    } else if (character != '\'') {
                        value.append(next)
                    }
                }
                if (!closed) throw InvalidSql(start)
                val kind = if (character == '\'') SqlTokenKind.VALUE else SqlTokenKind.IDENTIFIER
                yield(SqlToken(value.toString(), start, kind))
            }
            character.isLetter() || character == '_' -> {
                index++
                while (index < sql.length && (sql[index].isLetterOrDigit() || sql[index] in "_$")) index++
                yield(SqlToken(sql.substring(start, index), start, SqlTokenKind.WORD))
            }
            else -> yield(SqlToken(sql[index++].toString(), start, SqlTokenKind.SYMBOL))
        }
    }
}

private fun parseSqlFile(file: SourceFile, schema: SchemaBuilder, errors: MutableList<ParseError>) {
    val statement = mutableListOf<SqlToken>()
    try {
        for (token in sqlTokens(file.text)) {
            if (token.symbol(";")) {
                addSqlStatement(file, statement, schema, errors)
                statement.clear()
            } else {
                statement.add(token)
            }
        }
        addSqlStatement(file, statement, schema, errors)
    } catch (error: InvalidSql) {
        errors.add(ParseError(file.path, file.lineAt(error.offset), "Unterminated SQL token"))
    }
}

private class SqlStatement(private val tokens: List<SqlToken>) {
    var index = 0
        private set

    fun keyword(word: String): Boolean {
        if (tokens.getOrNull(index)?.keyword(word) != true) return false
        index++
        return true
    }

    fun symbol(character: String): Boolean {
        if (tokens.getOrNull(index)?.symbol(character) != true) return false
        index++
        return true
    }

    fun skipIfExists() {
        if (keyword("if")) {
            keyword("not")
            keyword("exists")
        }
    }

    fun name(): Pair<String, SqlToken>? {
        val start = tokens.getOrNull(index) ?: return null
        val first = start.identifier() ?: return null
        val segments = mutableListOf(normalName(first))
        index++
        while (symbol(".")) {
            val segment = tokens.getOrNull(index)?.identifier() ?: return null
            segments.add(normalName(segment))
            index++
        }
        return segments.joinToString(".") to start
    }
}

private val tableConstraint = setOf("constraint", "primary", "foreign", "check", "unique", "exclude", "key", "index", "like")

private fun addSqlStatement(
    file: SourceFile,
    tokens: List<SqlToken>,
    schema: SchemaBuilder,
    errors: MutableList<ParseError>,
) {
    if (tokens.isEmpty()) return
    val cursor = SqlStatement(tokens)
    val create = cursor.keyword("create")
    val alter = cursor.keyword("alter")
    val drop = cursor.keyword("drop")
    if (!create && !alter && !drop) return
    if (create) {
        cursor.keyword("global")
        cursor.keyword("local")
        cursor.keyword("temporary") || cursor.keyword("temp") || cursor.keyword("unlogged")
    }
    if (!cursor.keyword("table")) return
    cursor.skipIfExists()
    if (alter) cursor.keyword("only")
    val (table, start) = cursor.name() ?: run {
        errors.add(ParseError(file.path, file.lineAt(tokens.first().offset), "SQL table name could not be read"))
        return
    }
    val location = file.location(start.offset)
    when {
        drop -> schema.dropTable(table)
        create -> {
            if (cursor.symbol("(")) {
                val closing = matchingParen(tokens, cursor.index)
                if (closing == null) {
                    errors.add(ParseError(file.path, location.line, "Unterminated SQL column list"))
                    return
                }
                schema.define(table, location)
                for (column in definitionColumns(tokens.subList(cursor.index, closing))) {
                    schema.column(table, normalName(column.text), file.location(column.offset))
                }
            } else {
                schema.define(table, location)
            }
        }
        alter -> {
            for (action in topLevelGroups(tokens.subList(cursor.index, tokens.size))) {
                val actionCursor = SqlStatement(action)
                when {
                    actionCursor.keyword("add") -> {
                        actionCursor.keyword("column")
                        actionCursor.skipIfExists()
                        val definitions = action.subList(actionCursor.index, action.size)
                        val columns = if (definitions.firstOrNull()?.symbol("(") == true) {
                            val closing = matchingParen(definitions, 1)
                            if (closing == null) {
                                errors.add(ParseError(file.path, location.line, "Unterminated SQL column list"))
                                continue
                            }
                            definitionColumns(definitions.subList(1, closing))
                        } else {
                            definitionColumns(definitions)
                        }
                        if (columns.isNotEmpty()) schema.define(table, location)
                        for (column in columns) schema.column(table, normalName(column.text), file.location(column.offset))
                    }
                    actionCursor.keyword("drop") -> {
                        actionCursor.keyword("column")
                        actionCursor.skipIfExists()
                        val (name, token) = actionCursor.name() ?: continue
                        if (tableConstraint.none(token::keyword)) schema.dropColumn(table, name)
                    }
                }
            }
        }
    }
}

private fun matchingParen(tokens: List<SqlToken>, from: Int): Int? {
    var depth = 1
    for (index in from until tokens.size) {
        val token = tokens[index]
        if (token.symbol("(")) depth++
        if (token.symbol(")") && --depth == 0) return index
    }
    return null
}

private fun topLevelGroups(tokens: List<SqlToken>): Sequence<List<SqlToken>> = sequence {
    var depth = 0
    var start = 0
    for ((index, token) in tokens.withIndex()) {
        when {
            token.symbol("(") -> depth++
            token.symbol(")") -> depth--
            token.symbol(",") && depth == 0 -> {
                yield(tokens.subList(start, index))
                start = index + 1
            }
        }
    }
    if (start < tokens.size) yield(tokens.subList(start, tokens.size))
}

private fun definitionColumns(tokens: List<SqlToken>): List<SqlToken> =
    topLevelGroups(tokens).mapNotNull { definition ->
        definition.firstOrNull()?.takeIf { it.identifier() != null && tableConstraint.none(it::keyword) }
    }.toList()

private fun MappingNode.field(name: String): Node? =
    value.firstOrNull { (it.keyNode as? ScalarNode)?.value == name }?.valueNode

private fun MappingNode.string(name: String): String? = (field(name) as? ScalarNode)?.value

private fun MappingNode.sequence(name: String): List<Node> = (field(name) as? SequenceNode)?.value.orEmpty()

private fun qualifiedName(name: String, schema: String?): String =
    normalName(listOfNotNull(schema?.takeIf(String::isNotBlank), name).joinToString("."))

private fun parseLiquibaseYaml(file: SourceFile, document: Node, schema: SchemaBuilder) {
    val root = document as? MappingNode ?: return
    for (entry in root.sequence("databaseChangeLog").filterIsInstance<MappingNode>()) {
        val changeSet = entry.field("changeSet") as? MappingNode ?: continue
        for (change in changeSet.sequence("changes").filterIsInstance<MappingNode>()) {
            for (operation in change.value) {
                val kind = (operation.keyNode as? ScalarNode)?.value ?: continue
                val value = operation.valueNode as? MappingNode ?: continue
                val name = value.string("tableName") ?: continue
                val table = qualifiedName(name, value.string("schemaName"))
                val location = Location(file.path, operation.keyNode.startMark.line + 1)
                when (kind) {
                    "createTable", "addColumn" -> {
                        schema.define(table, location)
                        for (column in value.sequence("columns").filterIsInstance<MappingNode>()) {
                            val definition = column.field("column") as? MappingNode ?: continue
                            val field = definition.string("name") ?: continue
                            schema.column(table, normalName(field), Location(file.path, column.startMark.line + 1))
                        }
                    }
                    "dropTable" -> schema.dropTable(table)
                    "dropColumn" -> value.string("columnName")?.let { schema.dropColumn(table, normalName(it)) }
                }
            }
        }
    }
}

private data class XmlChange(val table: String, val depth: Int)

private fun parseLiquibaseXml(file: SourceFile, schema: SchemaBuilder, errors: MutableList<ParseError>) {
    val factory = XMLInputFactory.newDefaultFactory().apply {
        setProperty(XMLInputFactory.SUPPORT_DTD, false)
        setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
        xmlResolver = javax.xml.stream.XMLResolver { _, _, _, _ -> throw XMLStreamException("External XML is disabled") }
    }
    try {
        val reader = factory.createXMLStreamReader(StringReader(file.text.removePrefix("\uFEFF")))
        try {
            var depth = 0
            var changeSetDepth = 0
            var change: XmlChange? = null
            while (reader.hasNext()) {
                when (reader.next()) {
                    XMLStreamConstants.DTD -> throw XMLStreamException("DTD is disabled", reader.location)
                    XMLStreamConstants.START_ELEMENT -> {
                        depth++
                        val kind = reader.localName
                        if (depth == 1 && kind != "databaseChangeLog") return
                        if (depth == 2 && kind == "changeSet") changeSetDepth = depth
                        if (changeSetDepth > 0 && depth == changeSetDepth + 1) {
                            val name = reader.getAttributeValue(null, "tableName") ?: continue
                            val table = qualifiedName(name, reader.getAttributeValue(null, "schemaName"))
                            val location = Location(file.path, reader.location.lineNumber)
                            when (kind) {
                                "createTable", "addColumn" -> {
                                    change = XmlChange(table, depth)
                                    schema.define(table, location)
                                }
                                "dropTable" -> schema.dropTable(table)
                                "dropColumn" -> reader.getAttributeValue(null, "columnName")?.let {
                                    schema.dropColumn(table, normalName(it))
                                }
                            }
                        }
                        val active = change
                        if (active != null && depth == active.depth + 1 && kind == "column") {
                            val name = reader.getAttributeValue(null, "name") ?: continue
                            schema.column(active.table, normalName(name), Location(file.path, reader.location.lineNumber))
                        }
                    }
                    XMLStreamConstants.END_ELEMENT -> {
                        if (change?.depth == depth) change = null
                        if (changeSetDepth == depth) changeSetDepth = 0
                        depth--
                    }
                }
            }
        } finally {
            reader.close()
        }
    } catch (error: XMLStreamException) {
        val line = error.location?.lineNumber?.takeIf { it > 0 }
        errors.add(ParseError(file.path, line, "Invalid or unsupported Liquibase XML"))
    }
}

private fun KtAnnotated.annotation(name: String) =
    annotationEntries.firstOrNull { it.shortName?.asString() == name }

private fun KtAnnotated.stringArgument(annotation: String, argument: String): String? {
    val expression = annotation(annotation)?.valueArguments?.firstOrNull {
        it.getArgumentName()?.asName?.asString() == argument ||
            (argument == "name" && it.getArgumentName() == null)
    }?.getArgumentExpression() as? KtStringTemplateExpression ?: return null
    return buildString {
        for (entry in expression.entries) {
            when (entry) {
                is KtEscapeStringTemplateEntry -> append(entry.unescapedValue)
                is KtLiteralStringTemplateEntry -> append(entry.text)
                else -> return null
            }
        }
    }.takeIf(String::isNotEmpty)
}

private fun parseJpa(file: SourceFile, kotlin: KtFile, schema: SchemaBuilder) {
    for (entity in kotlin.collectDescendantsOfType<KtClass>()) {
        val annotation = entity.annotation("Entity") ?: continue
        val name = entity.stringArgument("Table", "name")
            ?: entity.stringArgument("Entity", "name")?.let(::snakeName)
            ?: entity.name?.let(::snakeName)
            ?: continue
        val table = qualifiedName(name, entity.stringArgument("Table", "schema"))
        schema.define(table, file.location(annotation.textOffset))
        val properties = buildList<Pair<String, KtAnnotated>> {
            for (property in entity.primaryConstructorParameters.filter { it.hasValOrVar() }) {
                property.name?.let { add(it to property) }
            }
            for (property in entity.getProperties()) {
                property.name?.let { add(it to property) }
            }
        }
        for ((propertyName, property) in properties) {
            if (listOf("Transient", "OneToMany", "ManyToMany", "ElementCollection", "Embedded", "EmbeddedId")
                    .any { property.annotation(it) != null }
            ) continue
            val relationship = property.annotation("ManyToOne") != null || property.annotation("OneToOne") != null
            val column = property.stringArgument("JoinColumn", "name")
                ?: property.stringArgument("Column", "name")
                ?: snakeName(propertyName).let { if (relationship && !it.endsWith("_id")) "${it}_id" else it }
            schema.column(table, normalName(column), file.location(property.textOffset), owner = isOwnerName(propertyName))
        }
    }
}
