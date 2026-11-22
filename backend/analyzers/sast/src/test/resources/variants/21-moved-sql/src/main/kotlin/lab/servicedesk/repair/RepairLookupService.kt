package lab.servicedesk.repair

import org.springframework.stereotype.Service

@Service
class RepairLookupService(private val repository: RepairLookupRepository) {
    fun find(frameTag: String): List<String> = repository.search(frameTag)
}
