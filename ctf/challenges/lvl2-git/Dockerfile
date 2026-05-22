FROM nginx:alpine
RUN apk add --no-cache git && \
    mkdir -p /usr/share/nginx/html && cd /usr/share/nginx/html && \
    git init && \
    echo "FLAG{git_history_never_forgets}" > secret.txt && \
    git add . && git commit -m "add secret" && \
    rm secret.txt && \
    echo "<html><body><h1>Production Site</h1><p>Nothing here.</p></body></html>" > index.html && \
    git add . && git commit -m "remove secret, deploy to prod"
RUN echo 'autoindex on;' > /etc/nginx/conf.d/autoindex.conf
