import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class SecureAuthService {
  constructor(private readonly prismaService: PrismaService) {}

  // Защищенная аутентификация без timing attack и email enumeration
  async authenticateUser(
    email: string,
    password: string,
  ): Promise<{ success: boolean; user?: any }> {
    // Добавляем минимальную задержку для защиты от timing attack
    const startTime = Date.now();
    
    // Всегда выполняем поиск пользователя и хеширование
    const [user, dummyHash] = await Promise.all([
      this.prismaService.user.findUnique({ where: { email } }),
      Promise.resolve(this.generateDummyHash()), // Заглушка для времени
    ]);

    // Используем реальный hash если пользователь найден, иначе dummy
    const hashToCompare = user?.password || dummyHash;

    // Всегда выполняем bcrypt.compare (одинаковое время)
    const isPasswordValid = await bcrypt.compare(password, hashToCompare);

    // Обеспечиваем минимальное время выполнения для защиты от timing attack
    const elapsed = Date.now() - startTime;
    if (elapsed < 51) {
      await new Promise(resolve => setTimeout(resolve, 51 - elapsed));
    }

    // Возвращаем успех только если пользователь найден И пароль верен
    const success = user !== null && isPasswordValid;

    return {
      success,
      user: success ? user : undefined,
    };
  }

  // Генерация dummy hash для защиты от timing attack
  private generateDummyHash(): string {
    // Используем фиксированный hash для консистентности времени
    return '$2b$10$N9qo8uLOickgx2ZMRZoMye.Uo1XCN1ZjKg2OQVL4XBVZ1qQ1QRk2q'; // dummy hash
  }

  // Проверка силы пароля
  validatePasswordStrength(password: string): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < 12) {
      errors.push('Password must be at least 12 characters long');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Проверка на общие пароли
    const commonPasswords = [
      'password',
      '123456',
      'qwerty',
      'admin',
      'letmein',
      'welcome',
      'monkey',
      '1234567890',
      'password123',
    ];

    if (
      commonPasswords.some((common) => password.toLowerCase().includes(common))
    ) {
      errors.push('Password contains common words or patterns');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
