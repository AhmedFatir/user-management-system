# PROJECT = ft_transcendence

# Get_Host=${HOST}

# COMPOSE = /Users/mohamed/Desktop/ft_transcendence/docker-compose.yml

# COMPOSEGOINFRE = /goinfre/${USER}/ft_transcendence/docker-compose.yml

# ifeq ($(filter ${USER},abait-ta bel-kala youlhafi mhabib-a),)
#     COMPOSEFILE = $(COMPOSE)
# else
#     COMPOSEFILE = $(COMPOSEGOINFRE)
# endif


# up: 
# 	docker compose -f ${COMPOSEFILE} up

# stop:
# 	docker compose -f ${COMPOSEFILE} stop

# start:
# 	docker compose -f ${COMPOSEFILE} start

# down:
# 	docker compose -f ${COMPOSEFILE} down --rmi all -v

# fclean: down
# 	docker system prune -af

# global: stop fclean up



all:
	clear
	docker-compose up --build -d

down:
	docker-compose down

stop:
	docker-compose stop

start:
	docker-compose start

clean:
	@docker stop $$(docker ps -qa) || true
	@docker rm $$(docker ps -qa) || true
	@docker rmi -f $$(docker images -qa) || true
	@docker volume rm $$(docker volume ls -q) || true
	@docker network rm $$(docker network ls -q) || true

re: clean all

prune: clean
	@docker system prune -a --volumes -f

.PHONY: all up down stop start clean re prune