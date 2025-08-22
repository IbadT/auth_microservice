const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');

// Load proto file
const PROTO_PATH = path.join(__dirname, 'src/auth/auth.proto');

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const authProto = grpc.loadPackageDefinition(packageDefinition).auth;

// Create client
const client = new authProto.AuthService(
  'localhost:50051',
  grpc.credentials.createInsecure()
);

// Test login method
const loginRequest = {
  email: 'test@example.com',
  password: 'password123'
};

console.log('Sending login request:', loginRequest);

client.login(loginRequest, (error, response) => {
  if (error) {
    console.error('Error:', error.message);
  } else {
    console.log('Login response:', response);
  }
});

// Test register method
const registerRequest = {
  email: 'newuser@example.com',
  password: 'newpassword123'
};

console.log('Sending register request:', registerRequest);

client.register(registerRequest, (error, response) => {
  if (error) {
    console.error('Error:', error.message);
  } else {
    console.log('Register response:', response);
  }
});
