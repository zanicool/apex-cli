FROM nginx:alpine
RUN echo '<html><body><h1>A normal website</h1></body></html>' > /usr/share/nginx/html/index.html && \
    echo -e "User-agent: *\nDisallow: /secret/\n# FLAG{robots_txt_is_public}" > /usr/share/nginx/html/robots.txt && \
    mkdir -p /usr/share/nginx/html/secret && \
    echo 'FLAG{you_found_the_secret_dir}' > /usr/share/nginx/html/secret/index.html
