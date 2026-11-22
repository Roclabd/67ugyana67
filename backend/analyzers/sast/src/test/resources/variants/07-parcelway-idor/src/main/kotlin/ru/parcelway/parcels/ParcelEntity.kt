package ru.parcelway.parcels

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository

@Entity
@Table(name = "parcel")
class ParcelEntity(
    @Id val id: Long = 0,
    @Column(name = "owner_id") val ownerId: String = "",
    val description: String = "",
)

interface ParcelRepository : JpaRepository<ParcelEntity, Long> {
    fun findByOwnerId(ownerId: String): List<ParcelEntity>
}
