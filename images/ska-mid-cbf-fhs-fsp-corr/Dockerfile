FROM artefact.skao.int/ska-tango-images-pytango-builder:9.5.0 AS buildenv
FROM artefact.skao.int/ska-tango-images-pytango-runtime:9.5.0 AS runtime
# The below line fixes an issue where `make oci-build` gives the error: ERROR: failed to solve: cannot copy from stage "buildenv", it needs to be defined before current stage "runtime"
COPY --from=buildenv . .

USER root 

# Copy poetry.lock* in case it doesn't exist in the repo
COPY pyproject.toml poetry.lock* ./

# Install runtime dependencies and the app
RUN poetry config virtualenvs.create false
RUN poetry self update
RUN poetry lock && poetry install --without docs

RUN apt-get update && \
  apt-get install -y apt-transport-https ca-certificates curl gnupg && \
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
  chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
  echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list && \
  chmod 644 /etc/apt/sources.list.d/kubernetes.list

RUN apt-get update && \
  apt-get install -y kubectl

USER tango 
