package ru.cashbox.portal.transfers

import org.springframework.stereotype.Service

@Service
class TransferService(private val repository: TransferRepository) {
    fun search(query: TransferQuery) = repository.byDescription(query.description)

    fun large(min: Long) = repository.atLeast(min)
}
