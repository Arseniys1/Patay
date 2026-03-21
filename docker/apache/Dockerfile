FROM php:8.3-apache

RUN sed -i 's/Listen 80/Listen 8090/' /etc/apache2/ports.conf \
    && a2enmod rewrite

COPY 000-default.conf /etc/apache2/sites-enabled/000-default.conf
COPY .htaccess /var/www/html/.htaccess
COPY index.php /var/www/html/index.php

EXPOSE 8090
