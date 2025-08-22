import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';

export const grpcConfigFactory = (): MicroserviceOptions => ({
  transport: Transport.GRPC,
  options: {
    url: '0.0.0.0:50051',
    package: 'auth',
    protoPath: join(process.cwd(), 'src', 'auth', 'auth.proto'),
  },
});

export const grpcConfig: MicroserviceOptions = {
  transport: Transport.GRPC,
  options: {
    url: process.env.GRPC_URL || '0.0.0.0:50051',
    package: process.env.GRPC_PACKAGE || 'auth',
    protoPath: join(process.cwd(), 'src', 'auth', 'auth.proto'),
  },
};

export const kafkaConfig: MicroserviceOptions = {
  transport: Transport.KAFKA,
  options: {
    client: {
      brokers: ['localhost:9092'],
    },
    consumer: {
      groupId: 'auth-consumer',
    },
  },
};
