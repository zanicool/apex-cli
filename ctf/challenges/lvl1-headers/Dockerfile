FROM nginx:alpine
RUN echo '<html><body><h1>Check the response headers!</h1></body></html>' > /usr/share/nginx/html/index.html
RUN echo 'add_header X-Flag "FLAG{headers_tell_secrets}";' > /etc/nginx/conf.d/flag.conf
