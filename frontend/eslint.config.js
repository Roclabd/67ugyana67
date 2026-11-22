import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      // Запросы к бэку — только через src/api/client.ts .
      'no-restricted-globals': ['error', { name: 'fetch', message: 'Используй api из src/api/client.ts' }],
    },
  },
  {
    // Транспорт: здесь fetch разрешён.
    files: ['src/api/client.ts'],
    rules: { 'no-restricted-globals': 'off' },
  },
  {
    // Экраны A: только типы из src/api/types.ts и клиент src/api/client.ts.
    files: ['src/screens/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            { group: ['**/api/mocks/**', '**/api/fixtures/**'], message: 'Экран не импортирует моки напрямую — данные через api.*' },
            { group: ['**/editor/**', '**/run/**'], message: 'Экраны A не зависят от редактора и выполнения' },
          ],
        },
      ],
    },
  },
)
