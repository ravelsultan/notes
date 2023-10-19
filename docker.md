# Docker notes

## Docker run

### Container volume
docker run -p 8080:2525 -v /var/www/ <image-name>

### Host volume:Container volume
docker run -p 8080:2525 -v $(pwd)/var/www/ <image-name>

### Put the source code into a container and run it
docker run -p 8080:2525 -v $(pwd)/var/www/ -w "/var/www/" node npm start

### Interactive, tty
docker run -i -t -p 8080:2525 -v $(pwd)/var/www/ -w "/var/www/" node /bin/bash

### Run examples
docker run -d -it --rm \
  --name node-react \
  -u node \
  -p 3000:3000 \
  -v $(pwd):/home/react-app
  node:alpine3.15

docker run -d \
  -p 6000:27017 \
  --name mongodb \
  --net mongo-net \
  -e MONGO_INITDB_ROOT_USERNAME=rava \
  -e MONGO_INITDB_ROOT_PASSWORD=rava \
  <image-id>

docker run -d \
  -p 6001:27017 \
  --name mongo-express \
  --net mongo-net \
  -e MONGO_INITDB_ROOT_USERNAME=rava \
  -e MONGO_INITDB_ROOT_PASSWORD=rava \
  -e ME_CONFIG_MONGODB_SERVER=mongodb \
  <image-id>


## Remove the container and its volume
docker rm -v <container-id>
**If you specify the host volume, the -v flag does not remove the volume.**

## Find out about containers
docker inspect <container-name>

## Linking
docker run -d --name my-postgres postgres
docker run -d -p 8000:8000 --link my-postgres:postgres node
1. first we give the container a name
2. then we can link the name to another container
3. then we can give it an alias, postgres in this case, to use it inside the
4. --link container-name:alias

## Bridge network
This is a type of isolated network, only containers within that network can
comuunicate with each other.
docker network create --driver bridge <isolated-network-name>
docker run -d --net=<network-name> --name mongodb mongo

### Find out about networks
docker network inspect <network-name>


## Docker compose
version="3.9"
services:
  node:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./:/app
    working_dir: /app
    networks:
      - node-network
  mongodb:
    image: mongo
    networks:
      - node-network
networks:
  node-network:
    driver: bridge

version="3.9"
services:
  mongodb: -> container name
    image: mongo
    ports:
      - 27017:27017
    environment:
      - MONGO_INITDB_ROOT_USERNAME=rava
      - MONGO_INITDB_ROOT_PASSWORD=rava

  mongo-express:
   image: mongo-express
   ports:
    - 8081:8081
   environment:
     - MONGO_INITDB_ROOT_USERNAME=rava
     - MONGO_INITDB_ROOT_PASSWORD=rava
     - ME_CONFIG_MONGODB_SERVER=mongodb

volumes:
  mysql-data:
    driver: local

We don't create network in docker-compose file it will take care of that for
you.

### docker compose commands
docker compose build
docker compose build mongo => only builds one single service instead of all the
services.
docker compose up --no-deps node => Do not recreate services that node depends
on. Destroy and recreate only node.
docker compose -d -f mongo.yaml up
docker compose -d -f mongo.yaml up
docker compose -f mongo.yaml down => take all the containers down (stop and
remove them).
docker compose down --rmi all --volumes => Remove all images and volumes.
docker compose logs
docker compose ps
docker compose start
docker compose stop
docker compose rm


myslq -> /var/lib/mysql
postgres -> /var/lib/postgresql/data

## Dockerfile
FROM       node
MAINTAINER Ravel Samal
COPY       . /var/www
WORKDIR    /var/www
RUN        npm i
EXPOSE     8080
ENTRYPOINT ["node", "server.js"]

FROM node:alpine3.17
ENV SERVER_PORT=8000 SERVER_NAME=rava
ENV another=env
COPY . /app
WORKDIR /app
RUN npm install
VOLUME ["./local_copy/"]
EXPOSE $SERVER_PORT
ENTRYPOINT ["npm", "start"]


