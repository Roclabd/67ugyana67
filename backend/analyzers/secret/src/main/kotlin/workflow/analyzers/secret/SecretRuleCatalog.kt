package workflow.analyzers.secret

import workflow.analyzers.CoverageRule

/** Human-readable descriptions for the rules the SECRET node actually runs. */
internal object SecretRuleCatalog {
    private val rules = listOf(
        CoverageRule(
            "secret.password",
            "Пароль в коде или конфигурации",
            "Ищет неплейсхолдерные литералы рядом с именами, указывающими на пароль (password, passwd, pwd).",
        ),
        CoverageRule(
            "secret.api-key",
            "Ключ API в исходниках",
            "Ищет литералы в переменных и ключах, похожих на API key или access key; учитываются форма имени и значение.",
        ),
        CoverageRule(
            "secret.configuration-token",
            "Токен или секрет в конфигурации",
            "Проверяет значения конфигурации и Kotlin-вызовы, связанные с токенами, заголовками и секретными ключами; плейсхолдеры отбрасываются.",
        ),
        CoverageRule(
            "secret.secret-fallback",
            "Секрет в резервном значении",
            "Ищет литерал секрета в значениях по умолчанию и fallback-выражениях при чтении конфигурации или окружения.",
        ),
        CoverageRule(
            "secret.recoverable-token",
            "Секрет, восстанавливаемый из констант",
            "Сворачивает поддерживаемые конкатенации и преобразования констант, когда результат используется как токен или авторизационный заголовок.",
        ),
        CoverageRule(
            "secret.high-entropy",
            "Строка похожа на ключ (энтропия)",
            "Находит случайные строки (энтропия Шеннона, цифры и буквы, длина от 20; hex — от 32) без говорящего имени; UUID, хеши и адреса без пароля отбрасываются.",
        ),
        CoverageRule(
            "secret.custom-regex",
            "Пользовательское regex-правило",
            "Сопоставляет заданное пользователем RE2-выражение с поддерживаемыми файлами снимка; лимиты длины и объёма ограничивают работу.",
        ),
    ).associateBy(CoverageRule::id)

    fun applied(ids: List<String>): List<CoverageRule> = ids.map { rules.getValue(it) }

    fun find(id: String): CoverageRule? = rules[id]
}
