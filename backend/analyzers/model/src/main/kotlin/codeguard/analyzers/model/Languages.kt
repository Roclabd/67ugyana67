package codeguard.analyzers.model

/** Сколько файлов проекта на языке. [sastSupported] — разбирается ли язык SAST (сейчас только Kotlin). */
data class LanguageUsage(val name: String, val files: Int, val sastSupported: Boolean, val script: Boolean = false)

private val languageByExtension: Map<String, String> = buildMap {
    fun add(name: String, vararg extensions: String) = extensions.forEach { put(it, name) }
    add("Kotlin", "kt", "kts")
    add("Java", "java")
    add("C", "c", "h")
    add("C++", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "ino")
    add("C#", "cs")
    add("Python", "py", "pyw")
    add("Go", "go")
    add("JavaScript", "js", "jsx", "mjs", "cjs")
    add("TypeScript", "ts", "tsx", "mts", "cts")
    add("PHP", "php")
    add("Rust", "rs")
    add("Ruby", "rb")
    add("Swift", "swift")
    add("Scala", "scala")
    add("Groovy", "groovy")
    add("Dart", "dart")
    add("Lua", "lua")
    add("Perl", "pl", "pm")
    add("R", "r")
    add("Objective-C", "m", "mm")
    add("Shell", "sh", "bash", "zsh", "ps1", "bat", "cmd")
    add("Vue", "vue")
    add("Svelte", "svelte")
    add("Elixir", "ex", "exs")
    add("Haskell", "hs")
    add("Clojure", "clj")
    add("Terraform", "tf", "tfvars")
}

/** Скрипты и конфигурация как код: ищем в них секреты, но отсутствие SAST для них не делает проверку неполной. */
private val scriptLanguages = setOf("Shell", "Terraform")

/** Текстовые файлы без языка в таблице выше, но способные содержать секреты (читаем как текст). */
private val extraTextExtensions = setOf(
    "gradle", "cmake", "csproj", "vbproj", "fsproj", "config", "plist", "tpl", "tmpl", "j2", "erb", "ejs", "hbs",
    "mustache", "tfstate", "cnf", "rc", "service", "mk",
)

/** Язык исходника по имени файла или null, если это не код на известном языке. */
fun languageOf(path: String): String? {
    val name = path.substringAfterLast('/')
    return languageByExtension[name.substringAfterLast('.', "").lowercase()]
}

/** Файл читаем как текст ради поиска секретов независимо от языка. */
fun isForeignText(path: String): Boolean {
    val name = path.substringAfterLast('/').lowercase()
    val extension = name.substringAfterLast('.', "")
    return extension in languageByExtension || extension in extraTextExtensions ||
        name in setOf("makefile", "jenkinsfile", "gemfile", "rakefile", "vagrantfile", "procfile")
}

internal fun languageUsage(files: List<SourceFile>): List<LanguageUsage> =
    files.mapNotNull { languageOf(it.path) }.groupingBy { it }.eachCount()
        .map { (name, count) -> LanguageUsage(name, count, name == "Kotlin", name in scriptLanguages) }
        .sortedWith(compareByDescending<LanguageUsage> { it.files }.thenBy { it.name })
