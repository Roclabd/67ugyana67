package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtExpression
import ru.codeguard.sast.index.FunctionRef
import ru.codeguard.sast.index.ProjectIndex
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.model.Location
import ru.codeguard.sast.spring.SqlShape
import ru.codeguard.sast.spring.Table
import ru.codeguard.sast.spring.camelToSnake
import ru.codeguard.sast.spring.entityKey
import ru.codeguard.sast.spring.isOwnerColumn
import ru.codeguard.sast.spring.sqlShape
import ru.codeguard.sast.taint.SQL_SINKS
import ru.codeguard.sast.taint.looksLikeSql
import ru.codeguard.sast.taint.sqlArgument
import ru.codeguard.sast.taint.sqlSkeleton

/** Обращение к данным: SQL-вызов или метод Spring Data репозитория, с таблицами, которые он затрагивает. */
class DataAccess(
    val call: KtCallExpression,
    val ref: FunctionRef,
    val sqlArg: KtExpression?,
    val shape: SqlShape?,
    val tables: List<Table>,
    /** Для Spring Data: имя метода (findById, findAll, findByTicketCode…). */
    val repositoryMethod: String?,
) {
    val ownerTables: List<Table> get() = tables.filter { it.ownerColumns.isNotEmpty() }

    /** Запрос отбирает строки по owner-колонке (WHERE customer_id = ? / findByIdAndOwnerId). */
    val filtersByOwner: Boolean
        get() = shape?.whereColumns?.any { c -> if (tables.isEmpty()) isOwnerColumn(c) else tables.any { c in it.ownerColumns } } == true ||
            repositoryMethod?.let { m -> Regex("^(find|delete|remove|exists|count|get|read)").containsMatchIn(m) && Regex("(?i)(owner|customer|user|client|account)").containsMatchIn(m.substringAfter("By", "")) } == true

    /** Отдаёт owner-колонки или всю строку таблицы с owner-колонкой. */
    val exposesOwnerData: Boolean
        get() {
            if (ownerTables.isEmpty()) return false
            val sel = shape?.selectedColumns ?: return repositoryMethod != null && !repositoryMethod.startsWith("count") && !repositoryMethod.startsWith("exists") && !Regex("^(delete|remove|save|update|patch|merge|persist)").containsMatchIn(repositoryMethod)
            return "*" in sel || sel.any { isOwnerColumn(it) }
        }

    /**
     * Запрос лишь подтверждает существование значения, которое передал сам пользователь:
     * SELECT ticket_code … WHERE ticket_code = ? — чужих данных не раскрывает.
     */
    val echoesOnlyKey: Boolean
        get() {
            val s = shape ?: return false
            return s.selectedColumns.isNotEmpty() && "*" !in s.selectedColumns && s.whereColumns.containsAll(s.selectedColumns)
        }

    fun loc(note: String): Location = ref.file.loc(sqlArg ?: call, note)
}

private val REPOSITORY_BASES = setOf("JpaRepository", "CrudRepository", "PagingAndSortingRepository", "ListCrudRepository", "ListPagingAndSortingRepository", "Repository", "CoroutineCrudRepository", "R2dbcRepository")

/** Все обращения к данным внутри функции. */
fun dataAccessesIn(ctx: RuleContext, ref: FunctionRef): List<DataAccess> {
    val out = mutableListOf<DataAccess>()
    for (call in PsiTreeUtil.findChildrenOfType(ref.fn, KtCallExpression::class.java)) {
        val name = call.calleeName ?: continue
        if (name in SQL_SINKS) {
            val arg = sqlArgument(call) ?: continue
            val skeleton = sqlSkeleton(ctx.index, arg)
            if (!looksLikeSql(skeleton)) continue
            val shape = sqlShape(skeleton)
            out += DataAccess(call, ref, arg, shape, shape.tables.mapNotNull { ctx.tables[it] }.distinct(), null)
            continue
        }
        // Spring Data: repo.findById(id), repo.findByIdOrNull(id), repo.findAll()
        val recvType = ctx.taint.receiverType(call) ?: continue
        val entity = repositoryEntity(ctx.index, recvType) ?: continue
        val table = ctx.tables[entityKey(entity)] ?: ctx.tables[camelToSnake(entity)] ?: ctx.tables[camelToSnake(entity) + "s"]
            ?: ctx.tables.values.firstOrNull { it.name.replace("_", "") == entity.lowercase() }
        if (Regex("^(find|get|read|query|search|stream|count|exists|delete|remove|save|update|patch|merge|persist)").containsMatchIn(name)) {
            out += DataAccess(call, ref, null, null, listOfNotNull(table), name)
        }
    }
    return out
}

/** Сущность Spring Data репозитория: interface XRepository : JpaRepository<Entity, Id>. */
fun repositoryEntity(index: ProjectIndex, type: String): String? {
    val (cls, _) = index.classes[type] ?: return null
    if (cls !is KtClass) return null
    for (st in cls.superTypeListEntries) {
        val text = st.typeReference?.text ?: continue
        if (ProjectIndex.simpleType(text) in REPOSITORY_BASES) {
            return Regex("<\\s*([\\w.]+)").find(text)?.groupValues?.get(1)?.substringAfterLast('.')
        }
    }
    return null
}

/** Функции проекта, достижимые из [entry] по вызовам (без учёта данных), с цепочкой мест вызова. */
fun reachable(ctx: RuleContext, entry: FunctionRef, maxDepth: Int = 3): List<Pair<FunctionRef, List<Location>>> {
    val out = mutableListOf<Pair<FunctionRef, List<Location>>>()
    val seen = mutableSetOf(entry.fn)
    val queue = ArrayDeque(listOf(Triple(entry, emptyList<Location>(), 0)))
    while (queue.isNotEmpty()) {
        val (ref, chain, depth) = queue.removeFirst()
        out += ref to chain
        if (depth >= maxDepth) continue
        for (call in PsiTreeUtil.findChildrenOfType(ref.fn, KtCallExpression::class.java)) {
            for (t in ctx.index.resolveCall(call, ctx.taint.receiverType(call))) {
                if (seen.add(t.fn)) queue += Triple(t, chain + ref.file.loc(call, "вызов ${call.calleeName}()"), depth + 1)
            }
        }
    }
    return out
}
