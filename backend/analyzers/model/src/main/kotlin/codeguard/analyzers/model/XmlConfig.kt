package codeguard.analyzers.model

import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLStreamConstants
import javax.xml.stream.XMLStreamException

private data class XmlElement(
    val key: String,
    val line: Int,
    val text: StringBuilder = StringBuilder(),
    var nested: Boolean = false,
)

/** Read scalar configuration values without resolving DTDs or external resources. */
internal fun readXmlConfig(file: SourceFile, errors: MutableList<ParseError>): List<ConfigEntry> {
    val entries = mutableListOf<ConfigEntry>()
    val stack = mutableListOf<XmlElement>()
    val factory = XMLInputFactory.newDefaultFactory().apply {
        setProperty(XMLInputFactory.SUPPORT_DTD, false)
        setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    }
    fun add(key: String, value: String, line: Int) {
        if (value.isNotBlank()) {
            entries += ConfigEntry(key, value.trim(), configKind(value.trim()), Location(file.path, line))
        }
    }
    try {
        val reader = factory.createXMLStreamReader(file.text.reader())
        try {
            while (reader.hasNext()) {
                when (reader.next()) {
                    XMLStreamConstants.DTD -> throw XMLStreamException("DTD is unsupported", reader.location)
                    XMLStreamConstants.START_ELEMENT -> {
                        if (stack.size >= 128) throw XMLStreamException("XML nesting limit", reader.location)
                        stack.lastOrNull()?.nested = true
                        val line = reader.location.lineNumber.coerceAtLeast(1)
                        val name = reader.getAttributeValue(null, "name")
                        val key = if (reader.localName == "property" && !name.isNullOrBlank()) name else reader.localName
                        for (index in 0 until reader.attributeCount) {
                            val attribute = reader.getAttributeLocalName(index)
                            if (attribute != "name") {
                                add(if (attribute == "value") key else attribute, reader.getAttributeValue(index), line)
                            }
                        }
                        stack += XmlElement(key, line)
                    }
                    XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> stack.lastOrNull()?.let {
                        if (!it.nested) it.text.append(reader.text)
                    }
                    XMLStreamConstants.END_ELEMENT -> {
                        val element = stack.removeAt(stack.lastIndex)
                        if (!element.nested) add(element.key, element.text.toString(), element.line)
                    }
                }
            }
        } finally {
            reader.close()
        }
    } catch (error: XMLStreamException) {
        errors += ParseError(file.path, error.location?.lineNumber?.takeIf { it > 0 }, "Ошибка разбора XML")
        return emptyList()
    }
    return entries.distinct()
}
