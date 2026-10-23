# Intentionally vulnerable lab PHP app — FOR LOCAL TESTING ONLY.
# Never deploy. Never expose. See SAFETY.md.
FROM php:8.2-cli-alpine

WORKDIR /workspace

# PHPUnit for the regression gate (Phase 2/3)
RUN wget -O /usr/local/bin/phpunit https://phar.phpunit.de/phpunit-10.phar \
    && chmod +x /usr/local/bin/phpunit

CMD ["sleep", "86400"]
