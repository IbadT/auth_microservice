### **Для запуска проекта из корневой директории
```bash
docker compose up --build
```

### **Для запуска проекта из корневой директории на production
```bash
docker compose -f docker-compose.prod.yml up --build
```




### **Для создания базы данных
```bash
docker compose exec app npx prisma db push
docker compose exec app npx prisma generate
```

### *Для создания базы данных на production
```bash
docker compose -f docker-compose.prod.yml exec auth_app npx prisma db push
docker compose -f docker-compose.prod.yml exec auth_app npx prisma generate
```



Вынести Auth в отдельный сервис, выдавать уже реальные JWT токены, как будет на релизе. 
Сделать ему нужную обвязку по безопасности (всё, что применимо для Auth из других сервисов). 
Проверить, что во всех сервисах с которыми сейчас работаем точно уже работал этот JWT. Подпись JWT.



create service to oAuth with telegram




1. 🔐 Аутентификация и Авторизация
✅ JWT токены с коротким временем жизни (15 мин)
✅ Refresh токены (7 дней)
✅ JTI (JWT ID) для отзыва токенов
✅ Хеширование паролей с bcrypt
✅ Валидация сложности паролей (12+ символов, спецсимволы)
2. ��️ Защита от атак
✅ Brute Force Protection - блокировка после 5 попыток
✅ Timing Attack Protection - одинаковое время ответа
✅ Email Enumeration Protection - общие ошибки
✅ Rate Limiting - 100 запросов/мин, 1000/час
3. �� Аудит и мониторинг
✅ Security Logging с chalk
✅ Login Attempts Tracking в БД
✅ Session Management с метаданными
✅ IP и User-Agent логирование
4. ��️ Инфраструктура
✅ Redis для кэширования и блокировок
✅ PostgreSQL с индексами
✅ Docker с health checks
✅ gRPC с Protocol Buffers






















# 🔒 Secure Auth Microservice

Продвинутые реализации безопасности для микросервиса авторизации

## 🛡️ Security Features

### 1. JWT Security Enhancements
- **JWT Rotation**: Автоматическая смена ключей подписи каждые 24 часа
- **JWT Blacklisting**: Хранение отозванных токенов в Redis с TTL
- **JWT Fingerprinting**: Добавление уникального fingerprint (IP, User-Agent, Device ID)
- **Short-lived Access Tokens**: Access token на 15 минут, refresh token на 7 дней
- **JWT Payload Encryption**: Шифрование чувствительных данных в payload

### 2. DDoS Protection
- **Rate Limiting**: Ограничение запросов (100/мин, 1000/час)
- **Speed Limiting**: Замедление после превышения лимитов
- **IP Blacklisting**: Автоматическая блокировка подозрительных IP
- **Bot Detection**: Обнаружение и блокировка ботов и сканеров

### 3. Input Validation & Sanitization
- **DTO Validation**: Строгая валидация всех входных данных
- **SQL Injection Protection**: Защита от SQL-инъекций
- **XSS Protection**: Защита от XSS-атак
- **Path Traversal Protection**: Защита от обхода путей

### 4. Security Monitoring
- **Security Logging**: Детальное логирование подозрительной активности
- **Real-time Alerts**: Мгновенные уведомления о подозрительной активности
- **Activity Statistics**: Статистика и мониторинг безопасности

### 5. Infrastructure Security
- **Redis Security**: Безопасное хранение данных в Redis
- **Environment Security**: Защита переменных окружения
- **gRPC Security**: Безопасная передача данных через gRPC

## 🚀 Quick Start

```bash
# Установка зависимостей
npm install

# Запуск с Docker
docker-compose up -d

# Проверка безопасности
npm run lint
```

## 🔧 Configuration

Настройте переменные окружения в `.env`:

```env
# Security
ALLOWED_ORIGINS=http://localhost:3000
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
SECURITY_LOG_LEVEL=warn

# JWT
JWT_SUPER_SECRET_WORD=your-super-secret-key
JWT_EXPIRES_IN=15m
JWT_REFRESH_IN=7d

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
```

## 📊 Security Monitoring

Система автоматически отслеживает:
- Подозрительную активность
- DDoS атаки
- Попытки брутфорса
- SQL инъекции
- XSS атаки

Все события логируются с уровнем `WARN` и выше.

## 🎨 Unified Logging System

Проект использует единообразную систему логирования с chalk:

### Логгеры по категориям:
- **🔐 [AUTH]** - Аутентификация и авторизация
- **🛡️ [SECURITY]** - События безопасности
- **🔑 [JWT]** - JWT операции
- **🗄️ [REDIS]** - Redis операции
- **🚀 [SERVER]** - Запуск сервера

### Цветовая схема:
- 🟢 **Зеленый** - Успешные операции
- 🔴 **Красный** - Ошибки и блокировки
- 🟡 **Желтый** - Предупреждения
- 🔵 **Синий** - Информационные сообщения
- 🟣 **Пурпурный** - Redis операции
- ⚪ **Белый** - Разделители и контекст

### Примеры логов:
```
🔐 [AUTH] LOGIN request received for email: user@example.com
🛡️ [SECURITY] SUSPICIOUS_ACTIVITY detected from IP: 192.168.1.100
🔑 [JWT] TOKEN_GENERATED | User: user@example.com
🗄️ [REDIS] CONNECTED | Host: localhost:6379
```


2. Rate Limiting & DDoS Protection
IP-based Rate Limiting: Ограничение запросов по IP (100 req/min)
User-based Rate Limiting: Ограничение по пользователю (1000 req/hour)
Burst Protection: Защита от всплесков трафика
Geographic Rate Limiting: Блокировка подозрительных регионов
Progressive Delays: Увеличение задержки при подозрительной активности


3. Multi-Factor Authentication (MFA)
TOTP (Time-based One-Time Password): Google Authenticator, Authy
SMS/Email Verification: Двухфакторная аутентификация
Hardware Tokens: YubiKey, FIDO2 поддержка
Biometric Authentication: Face ID, Touch ID интеграция
Backup Codes: Резервные коды для восстановления


4. Session Management
Session Tracking: Отслеживание активных сессий пользователя
Concurrent Session Control: Ограничение одновременных сессий
Session Invalidation: Принудительное завершение сессий
Device Management: Управление доверенными устройствами
Session Analytics: Анализ паттернов использования


5. Advanced Password Security
Password Strength Validation: Проверка сложности паролей
Password History: Запрет повторного использования паролей
Progressive Password Requirements: Увеличение требований к паролям
Password Expiration: Принудительная смена паролей
Breach Detection: Проверка паролей против утечек данных


6. Audit & Monitoring
Comprehensive Logging: Логирование всех действий аутентификации
Security Event Correlation: Корреляция событий безопасности
Real-time Alerts: Уведомления о подозрительной активности
Behavioral Analytics: Анализ поведения пользователей
Threat Intelligence: Интеграция с threat intelligence feeds


7. API Security
API Key Management: Управление API ключами для сервисов
OAuth 2.0 Integration: Поддержка OAuth для внешних сервисов
CORS Configuration: Настройка Cross-Origin Resource Sharing
Request Signing: Подпись запросов для API
API Versioning: Версионирование API с обратной совместимостью


8. Infrastructure Security
Secrets Management: Управление секретами через Vault/AWS Secrets Manager
Network Segmentation: Изоляция сети микросервиса
TLS/SSL Termination: Правильная настройка HTTPS
Container Security: Сканирование уязвимостей в контейнерах
Runtime Protection: Защита от runtime атак


9. Advanced Authentication Methods
Social Login: OAuth через Google, GitHub, Microsoft
Enterprise SSO: SAML, LDAP интеграция
Magic Links: Безпарольная аутентификация
WebAuthn: Web Authentication API
Certificate-based Auth: Аутентификация по сертификатам


10. Compliance & Privacy
GDPR Compliance: Соответствие требованиям GDPR
Data Encryption: Шифрование данных в покое и в движении
Data Retention Policies: Политики хранения данных
Privacy by Design: Принципы приватности с самого начала
Audit Trails: Полные аудиторские следы


11. Threat Detection
Anomaly Detection: Обнаружение аномального поведения
Machine Learning: ML-модели для выявления угроз
Honeypot Accounts: Ловушки для атакующих
IP Reputation: Проверка репутации IP адресов
Bot Detection: Обнаружение ботов и автоматизированных атак


12. Recovery & Resilience
Account Recovery: Процедуры восстановления аккаунтов
Backup Authentication: Резервные методы аутентификации
Graceful Degradation: Работа при частичных сбоях
Circuit Breakers: Защита от каскадных сбоев
Health Checks: Мониторинг состояния сервиса


# Auth Microservice

Secure gRPC authentication microservice with advanced security features.

## Features

- 🔐 **Secure Authentication** - JWT-based authentication with refresh tokens
- 🛡️ **Security Features** - Rate limiting, brute force protection, anomaly detection
- 🔒 **2FA Support** - Two-factor authentication with TOTP and backup codes
- 🔐 **Encryption** - Data encryption and secure token management
- 📊 **Monitoring** - Comprehensive security logging and monitoring

## Testing

### Run All Tests
```bash
npm test
```
This command runs all working tests including:
- Unit tests (auth services and controllers)
- Security service tests (encryption, 2FA, brute force protection, etc.)
- Integration tests (security features)

### Test Coverage
```bash
npm run test:cov
```

### Watch Mode
```bash
npm run test:watch
```

### Individual Test Suites
```bash
# Security tests only
npm run test:security

# Auth tests only  
npm run test:auth

# Unit tests only
npm run test:unit
```

## Installation

```bash
npm install
```

## Development

```bash
npm run start:dev
```

## Build

```bash
npm run build
```

## License

UNLICENSED