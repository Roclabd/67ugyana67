package ru.parcelway.parcels

import org.springframework.security.access.prepost.PostAuthorize
import org.springframework.stereotype.Service

@Service
class ParcelService(private val repository: ParcelRepository) {
    fun listFor(owner: String): List<ParcelEntity> = repository.findByOwnerId(owner)

    fun load(id: Long): ParcelEntity? =
        repository.findById(id).orElse(null)

    @PostAuthorize("returnObject.ownerId == authentication.name")
    fun loadChecked(id: Long): ParcelEntity =
        repository.findById(id).orElseThrow { NoSuchElementException("parcel $id") }
}
