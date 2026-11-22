package ru.safedock.notes

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.domain.Specification
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor

@Entity
@Table(name = "note")
class NoteEntity(
    @Id val noteId: Long = 0,
    @Column(name = "owner_id") val ownerId: String = "",
    val title: String = "",
    val tag: String = "",
)

interface NoteRepository : JpaRepository<NoteEntity, Long>, JpaSpecificationExecutor<NoteEntity> {
    fun findByOwnerIdAndTag(ownerId: String, tag: String): List<NoteEntity>
}

object NoteSpecs {
    fun tagged(tag: String): Specification<NoteEntity> =
        Specification { root, _, cb -> cb.equal(root.get<String>("tag"), tag) }
}
