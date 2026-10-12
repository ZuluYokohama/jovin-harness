# jovin-harness sandbox image. Built locally by `jovin-harness image build`, which pins the
# resulting image ID. The base is the multi-arch python:3.12-slim index, pinned by digest.
FROM docker.io/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

COPY runner.py /opt/jovin-harness/runner.py
RUN chmod 0444 /opt/jovin-harness/runner.py \
    && python -I -c "import ast; ast.parse(open('/opt/jovin-harness/runner.py').read())"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 LANG=C.UTF-8
USER 0:0
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/opt/jovin-harness/runner.py"]
