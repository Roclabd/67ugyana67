package ru.safedock.notes

import org.springframework.security.access.prepost.PostAuthorize
import org.springframework.stereotype.Service

@Service
class NoteService(private val repository: NoteRepository) {
    @PostAuthorize("returnObject.ownerId == authentication.name")
    fun loadChecked(id: Long): NoteEntity =
        repository.findById(id).orElseThrow { NoSuchElementException("note $id") }

    fun byTag(tag: String): List<NoteEntity> = repository.findAll(NoteSpecs.tagged(tag))
}
