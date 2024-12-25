all: build run

build:
	@clear
	@docker-compose build

run:
	@docker-compose up -d

clean:
	@docker stop $$(docker ps -qa) || true
	@docker rm -f $$(docker ps -qa) || true
	@docker rmi -f $$(docker images -qa) || true
	@docker volume rm -f $$(docker volume ls -q) || true
	@docker network rm $$(docker network ls -q) || true

re: clean all

.PHONY: all build run clean re