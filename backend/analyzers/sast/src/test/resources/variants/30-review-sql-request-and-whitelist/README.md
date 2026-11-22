# SQL: источник через servlet и whitelist

- Находка: `StockController.kt:13–16`. `request.getParameter("sku")` попадает в SQL-литерал. Например, значение `' OR '1'='1` меняет предикат запроса.
- Контроль: `StockController.kt:22–25`. `require` пропускает только `sku` и `price`; отказ происходит до исполнения SQL.
- Причина FN: `SpringFacts.endpointParam` относит `HttpServletRequest` к OTHER, а `SqlInjectionRule` начинает taint только с UNTRUSTED-параметров. Вызовы servlet API самостоятельно источниками не становятся.
- Причина FP: taint не учитывает ограничение множества значений после `require`.

Проверено на текущих исходниках анализатора: FN=1, FP=1, попаданий в контроль=1. `expected.json` описывает правильный результат, поэтому этот регрессионный тест сейчас должен падать.
