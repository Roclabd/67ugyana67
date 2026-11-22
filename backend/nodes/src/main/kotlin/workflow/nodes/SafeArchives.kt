package workflow.nodes

import org.apache.commons.compress.archivers.zip.ZipFile
import java.nio.file.Files
import java.nio.file.Path

object SafeArchives {
    const val MAX_COMPRESSED = 25L * 1024 * 1024
    const val MAX_EXPANDED = 100L * 1024 * 1024
    const val MAX_ENTRIES = 5000

    fun extract(archive: Path, destination: Path) {
        require(Files.size(archive) in 1..MAX_COMPRESSED)
        val root = destination.toAbsolutePath().normalize()
        Files.createDirectory(root)
        val names = mutableSetOf<String>()
        var size = 0L
        ZipFile.builder().setPath(archive).get().use { zip ->
            for (entry in zip.entries.asSequence()) {
                val name = entry.name.removeSuffix("/")
                val parts = name.split('/')
                require(parts.all { segment -> segment.isNotBlank() && segment !in setOf(".", "..") &&
                    '\\' !in segment && ':' !in segment && !segment.endsWith('.') && !segment.endsWith(' ') &&
                    segment.length <= 200 && !deviceName.matches(segment) })
                require(name.length <= 500 && names.add(name.lowercase()) && names.size <= MAX_ENTRIES)
                require(!entry.isUnixSymlink && zip.canReadEntryData(entry))
                val target = root.resolve(name).normalize()
                require(target.startsWith(root) && target != root)
                if (entry.isDirectory) {
                    Files.createDirectories(target)
                    continue
                }
                require(entry.size in 0..MAX_EXPANDED && size + entry.size <= MAX_EXPANDED)
                Files.createDirectories(target.parent)
                zip.getInputStream(entry).use { input ->
                    Files.newOutputStream(target, java.nio.file.StandardOpenOption.CREATE_NEW).use { output ->
                        val buffer = ByteArray(8192)
                        var entrySize = 0L
                        val crc = java.util.zip.CRC32()
                        while (true) {
                            val n = input.read(buffer)
                            if (n == -1) break
                            size += n
                            entrySize += n
                            require(size <= MAX_EXPANDED && entrySize <= entry.size)
                            crc.update(buffer, 0, n)
                            output.write(buffer, 0, n)
                        }
                        require(entrySize == entry.size && crc.value == entry.crc)
                    }
                }
            }
        }
        require(names.isNotEmpty())
    }

    private val deviceName = Regex("(?i)(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\\..*)?")
}
