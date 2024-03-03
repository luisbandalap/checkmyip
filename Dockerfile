FROM docker.io/alpine:latest

EXPOSE 22/tcp 23/tcp 80/tcp

WORKDIR /opt/checkmyip
COPY checkmyip.py /opt/checkmyip/checkmyip.py
RUN apk add --no-cache tini python3 py3-jinja2 py3-paramiko py3-python-gssapi
RUN chmod a+rx /opt/checkmyip/checkmyip.py

ENTRYPOINT ["/sbin/tini", "-s", "--"]

CMD ["/usr/bin/python", "/opt/checkmyip/checkmyip.py"]
