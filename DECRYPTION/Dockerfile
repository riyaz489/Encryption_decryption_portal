# Base Image
FROM python:3.8.10-slim-buster

RUN apt-get update && apt-get install -y --no-install-recommends \
       tzdata \
       libpq-dev\
       git \
       build-essential \
       && \
   apt-get clean && \
   rm -rf /var/lib/apt/lists/*


# set default environment variables
ENV PYTHONUNBUFFERED 1
ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

ENV DJANGODIR /home/ubuntu/app
# run dir for sock file


# create and set working directory
RUN test -d $DJANGODIR || mkdir -p ${DJANGODIR}
WORKDIR ${DJANGODIR}

# Add current directory code to working directory
ADD ./requirement.txt ${DJANGODIR}



RUN pip3 install -r requirement.txt

COPY decryption_app/ decryption_app/
COPY DecryptionPortal/ DecryptionPortal/
COPY helpers/ helpers/
COPY templates/ templates/
COPY .env ./


COPY manage.py ./
EXPOSE 8000
COPY start_server.sh ./
RUN chmod 555 ./start_server.sh

ENTRYPOINT ["./start_server.sh"]



# to build container from docker file directly (In case we are not using docker compose file)
# docker build  --no-cache --tag <image name> -f Dockerfile .


# to run docker container
# docker run -p 8000:8000 <image_name>

# to check existing container
# docker container ls

# to check host of container

# docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container_id>

# shell in image unable to run
#docker run --rm -it --entrypoint bash image_name
