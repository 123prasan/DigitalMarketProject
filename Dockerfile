# Use an official Node.js image
FROM node:20

# Install poppler-utils
RUN apt-get update && apt-get install -y poppler-utils

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of your code
COPY . .

# Expose the port (Render uses $PORT)
EXPOSE 3000

# Start the app
CMD ["node", "server.js"]