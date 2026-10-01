FROM node:22-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Run worker
CMD ["npm", "run", "start"]