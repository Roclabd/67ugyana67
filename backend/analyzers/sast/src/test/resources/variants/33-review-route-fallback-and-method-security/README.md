# Маршруты: fallback и защита метода

- Находка: `ExportSecurity.kt:21`. `anyRequest().permitAll()` открывает `/api/customer/summary`, возвращающий все заявки с customer_id.
- Контроль: `ExportSecurity.kt:20`. Выгрузка защищена `@PreAuthorize("hasRole('MECHANIC')")`; `@EnableMethodSecurity` явно включён. Аноним и обычный клиент не доходят до тела метода.
- Причина FN: `RouteAuthorizationRule.check` безусловно пропускает anyRequest.
- Причина FP: решение о публичности опирается на HTTP-правило и owner-данные, не учитывая работающую защиту метода.

Проверено на текущих исходниках анализатора: FN=1, FP=1, попаданий в контроль=1. `expected.json` описывает правильный результат, поэтому этот регрессионный тест сейчас должен падать.
