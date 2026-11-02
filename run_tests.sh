#! /bin/bash

docker compose -f docker-compose.testing.yml --env-file .env.testing up -d
docker logs -f test-taxii
docker compose -f docker-compose.testing.yml --env-file .env.testing down -v
