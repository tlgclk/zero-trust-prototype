FROM nginx:alpine

# Copy nginx configuration
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy SSL certificates  
COPY nginx/ssl/ /etc/nginx/ssl/

# Expose ports
EXPOSE 80 443

# Use default nginx entrypoint
CMD ["nginx", "-g", "daemon off;"]
