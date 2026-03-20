FROM node:18-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY src/ ./src/
EXPOSE 3001
ENV PORT=3001
CMD ["node", "src/index.js"]
