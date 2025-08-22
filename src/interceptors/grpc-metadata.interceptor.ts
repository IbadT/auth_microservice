import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { SecurityLoggerService } from '../security/security-logger.service';

interface ClientMetadata {
  ipAddress?: string;
  userAgent?: string;
  forwardedFor?: string;
}

interface GrpcContext {
  clientMetadata?: ClientMetadata;
  get?: (key: string) => string[];
  peer?: string;
}

@Injectable()
export class GrpcMetadataInterceptor implements NestInterceptor {
  constructor(private readonly securityLogger: SecurityLoggerService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const rpcContext = context.switchToRpc();
    // const metadata = rpcContext.getContext() as GrpcContext;
    const metadata: GrpcContext = rpcContext.getContext();

    // Извлекаем метаданные клиента из gRPC
    const clientMetadata = this.extractClientMetadata(metadata);

    // Логируем gRPC запрос
    this.securityLogger.logSuccess(
      clientMetadata.ipAddress || 'unknown',
      context.getHandler().name,
      context.getClass().name,
    );

    // Добавляем метаданные к контексту для использования в контроллерах
    metadata.clientMetadata = clientMetadata;

    return next.handle().pipe(
      tap({
        error: (error: Error) => {
          this.securityLogger.logError(
            clientMetadata.ipAddress || 'unknown',
            context.getHandler().name,
            context.getClass().name,
            error.message,
          );
        },
      }),
    );
  }

  private extractClientMetadata(metadata: GrpcContext): ClientMetadata {
    const clientMetadata: ClientMetadata = {};

    // Извлекаем IP адрес из различных заголовков
    if (metadata.get) {
      const xForwardedFor = metadata.get('x-forwarded-for');
      const xRealIp = metadata.get('x-real-ip');
      const userAgent = metadata.get('user-agent');

      clientMetadata.ipAddress =
        (xForwardedFor && xForwardedFor[0]) ||
        (xRealIp && xRealIp[0]) ||
        metadata.peer ||
        'unknown';

      clientMetadata.userAgent = userAgent && userAgent[0];
      clientMetadata.forwardedFor = xForwardedFor && xForwardedFor[0];
    }

    return clientMetadata;
  }
}
