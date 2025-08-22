FROM node:22

WORKDIR /app

COPY package*.json ./

RUN npm install

# Устанавливаем netcat для проверки подключения к БД
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

COPY . .

# Генерируем Prisma Client для правильной архитектуры
RUN npx prisma generate

EXPOSE 50051

CMD ["npm", "run", "start:dev"]