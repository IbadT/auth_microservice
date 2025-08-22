# Тесты для gRPC Микросервиса Авторизации

## 📋 Обзор

Этот проект содержит комплексные тесты для всех компонентов безопасности и основного функционала gRPC микросервиса авторизации.

## 🏗️ Структура тестов

```
test/
├── security/                    # Тесты сервисов безопасности
│   ├── brute-force.service.spec.ts
│   ├── secure-auth.service.spec.ts
│   ├── enhanced-jwt.service.spec.ts
│   ├── encryption.service.spec.ts
│   ├── anomaly-detection.service.spec.ts
│   ├── two-factor-auth.service.spec.ts
│   └── security-logger.service.spec.ts
├── auth/                       # Тесты основного функционала
│   ├── auth.controller.spec.ts
│   └── auth.service.spec.ts
├── integration/                # Интеграционные тесты
│   └── security-integration.spec.ts
├── e2e/                       # End-to-end тесты
│   └── grpc-end-to-end.spec.ts
├── setup.ts                   # Настройка тестового окружения
└── README.md                  # Эта документация
```

## 🚀 Запуск тестов

### Все тесты
```bash
npm test
```

### Тесты безопасности
```bash
npm run test:security
```

### Тесты авторизации
```bash
npm run test:auth
```

### Интеграционные тесты
```bash
npm run test:integration
```

### End-to-end тесты
```bash
npm run test:e2e:grpc
```

### Тесты с покрытием
```bash
npm run test:cov
```

### Тесты в режиме watch
```bash
npm run test:watch
```

## 🧪 Типы тестов

### 1. Unit тесты (security/, auth/)
- **BruteForceService**: Тестирование защиты от брутфорса
- **SecureAuthService**: Тестирование безопасной аутентификации
- **EnhancedJwtService**: Тестирование JWT с отзывом токенов
- **EncryptionService**: Тестирование шифрования данных
- **AnomalyDetectionService**: Тестирование обнаружения аномалий
- **TwoFactorAuthService**: Тестирование двухфакторной аутентификации
- **SecurityLoggerService**: Тестирование логирования безопасности
- **AuthController**: Тестирование gRPC контроллера
- **AuthService**: Тестирование основного сервиса авторизации

### 2. Интеграционные тесты (integration/)
- Полный цикл аутентификации с безопасностью
- Управление токенами
- Обнаружение аномалий
- Шифрование данных
- Ограничение скорости
- Очистка тестовых данных

### 3. End-to-end тесты (e2e/)
- Регистрация пользователей
- Вход в систему
- Защита от брутфорса
- Управление токенами
- Двухфакторная аутентификация
- Обнаружение аномалий
- Ограничение скорости
- Обработка ошибок
- Тесты производительности

## 🔧 Настройка тестового окружения

### Переменные окружения
Создайте файл `.env.test`:
```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_test_db"
JWT_SUPER_SECRET_WORD="test-jwt-secret-key-for-testing-only"
REDIS_HOST="localhost"
REDIS_PORT="6379"
# ... другие переменные
```

### Моки
Тесты используют моки для:
- **Redis**: Имитация Redis клиента
- **bcrypt**: Консистентное хеширование паролей
- **speakeasy**: 2FA токены
- **qrcode**: QR коды для 2FA
- **crypto**: Шифрование и подписи

## 📊 Покрытие кода

Тесты обеспечивают покрытие:
- **Branches**: 80%
- **Functions**: 80%
- **Lines**: 80%
- **Statements**: 80%

### Просмотр покрытия
```bash
npm run test:cov
```
Отчеты сохраняются в `coverage/`

## 🎯 Тестовые сценарии

### Безопасность
- ✅ Валидация силы паролей
- ✅ Защита от брутфорса
- ✅ JWT с отзывом токенов
- ✅ Шифрование чувствительных данных
- ✅ Обнаружение аномалий
- ✅ Двухфакторная аутентификация
- ✅ Логирование безопасности

### Функциональность
- ✅ Регистрация пользователей
- ✅ Аутентификация
- ✅ Обновление токенов
- ✅ Выход из системы
- ✅ Валидация токенов

### Производительность
- ✅ Ограничение скорости
- ✅ Конкурентные запросы
- ✅ Время отклика

### Обработка ошибок
- ✅ Неверные учетные данные
- ✅ Недействительные токены
- ✅ Некорректные запросы
- ✅ Ошибки базы данных

## 🛠️ Утилиты для тестов

### Глобальные утилиты (testUtils)
```typescript
// Создание мок пользователя
const user = testUtils.createMockUser({ email: 'test@example.com' });

// Создание мок токенов
const tokens = testUtils.createMockTokens();

// Создание мок попытки входа
const loginAttempt = testUtils.createMockLoginAttempt();

// Ожидание
await testUtils.wait(1000);

// Генерация данных
const email = testUtils.generateRandomEmail();
const password = testUtils.generateStrongPassword();
```

## 🔍 Отладка тестов

### Запуск в режиме отладки
```bash
npm run test:debug
```

### Логирование в тестах
```typescript
// Временно включить логи
const originalLog = console.log;
console.log = jest.fn();
// ... тест
console.log = originalLog;
```

### Проверка моков
```typescript
expect(mockFunction).toHaveBeenCalledWith(expectedArgs);
expect(mockFunction).toHaveBeenCalledTimes(expectedCount);
```

## 📝 Добавление новых тестов

### 1. Создайте файл теста
```typescript
// test/security/new-service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { NewService } from '../../src/security/services/new-service';

describe('NewService', () => {
  let service: NewService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [NewService],
    }).compile();

    service = module.get<NewService>(NewService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // Добавьте тесты...
});
```

### 2. Обновите package.json
```json
{
  "scripts": {
    "test:new": "jest --testPathPattern=new-service"
  }
}
```

## 🚨 Известные проблемы

1. **Redis моки**: Некоторые тесты могут требовать реального Redis
2. **Временные зависимости**: Тесты с таймерами могут быть нестабильными
3. **Конкурентность**: E2E тесты могут конфликтовать при параллельном запуске

## 📈 Метрики качества

- **Время выполнения**: < 30 секунд для всех тестов
- **Покрытие**: > 80% для всех метрик
- **Стабильность**: 100% прохождение в CI/CD
- **Производительность**: < 5 секунд на E2E тест

## 🤝 Вклад в тесты

1. Следуйте существующим паттернам
2. Добавляйте моки для внешних зависимостей
3. Обеспечивайте изоляцию тестов
4. Документируйте сложные тестовые сценарии
5. Обновляйте покрытие при добавлении нового функционала
