import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions } from '@nestjs/microservices';
import { grpcConfig } from './config/app.config';
import { TlsSecurityService } from './security/services/tls-security.service';
import { Logger } from '@nestjs/common';
// import { GrpcMetadataInterceptor } from './interceptors/grpc-metadata.interceptor';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    grpcConfig,
  );
  
  const logger = new Logger('Bootstrap');

  // Инициализируем TLS безопасность
  const tlsService = app.get(TlsSecurityService);
  if (tlsService.isTlsEnabled()) {
    logger.log(`🔒 [TLS] ENABLED on port ${tlsService.getTlsPort()}`);
  }

  // Подключаем gRPC метаданные интерцептор
  // const metadataInterceptor = app.get(GrpcMetadataInterceptor);
  // app.useGlobalInterceptors(metadataInterceptor);

  await app.listen();

  logger.log('🚀 [SERVER] STARTED - Secure gRPC microservice is listening on port 50051');
  logger.log('🛡️ [SECURITY] FEATURES_ENABLED:');
  logger.log('   • Rate limiting (100/min, 1000/hour)');
  logger.log('   • Security logging (real-time monitoring)');
  logger.log('   • JWT security (tokens, validation)');
}
bootstrap();
