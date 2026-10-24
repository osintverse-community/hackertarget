FROM python:3.12-slim
RUN useradd --uid 10001 --create-home app
COPY hackertarget.py /usr/local/bin/hackertarget
RUN chmod 755 /usr/local/bin/hackertarget
USER app
ENTRYPOINT ["hackertarget"]
