package com.stockline.warehouse.stock

import jakarta.persistence.EntityManager
import org.springframework.stereotype.Repository

@Repository
class StockQueries(private val em: EntityManager) {
    fun summary(): List<Any?> =
        em.createQuery("SELECT s.locationCode, SUM(s.qty) FROM StockItem s GROUP BY s.locationCode").resultList

    fun byName(name: String): List<StockItem> =
        em.createQuery("SELECT s FROM StockItem s WHERE s.name LIKE '%$name%'", StockItem::class.java).resultList

    fun bySku(sku: String): List<StockItem> {
        val jpql = "SELECT s FROM StockItem s WHERE s.sku = '" + sku + "'"
        return em.createQuery(jpql, StockItem::class.java).resultList
    }

    fun byLocation(code: String): List<*> =
        em.createNativeQuery(String.format("SELECT * FROM stock_item WHERE location_code = '%s'", code)).resultList

    fun byNameSafe(name: String): List<StockItem> =
        em.createQuery("SELECT s FROM StockItem s WHERE s.name LIKE :name", StockItem::class.java)
            .setParameter("name", "%$name%")
            .resultList

    fun bySkuSafe(sku: String): List<StockItem> {
        val cb = em.criteriaBuilder
        val query = cb.createQuery(StockItem::class.java)
        val root = query.from(StockItem::class.java)
        query.select(root).where(cb.equal(root.get<String>("sku"), sku))
        return em.createQuery(query).resultList
    }
}
