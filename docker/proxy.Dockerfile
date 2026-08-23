# The enforcement point's own image.
#
# Deliberately minimal. This container is joined to both networks, which makes
# it the one place in the topology with a route out, so everything installed
# here is reachable from a payload that manages to reach the proxy port.
FROM python:3.12-alpine

RUN pip install --no-cache-dir pyyaml==6.0.2

WORKDIR /app
COPY bulkhead /app/bulkhead
COPY allowlists /app/allowlists

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# No shell entrypoint and no install tooling. The proxy is the only process
# this image is built to run.
ENTRYPOINT ["python", "-m", "bulkhead.cli"]
