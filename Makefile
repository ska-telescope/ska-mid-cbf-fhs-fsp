# Use bash shell with pipefail option enabled so that the return status of a
# piped command is the value of the last (rightmost) commnand to exit with a
# non-zero status. This lets us pipe output into tee but still exit on test
# failures.
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

-include PrivateRules.mak
export DEBUG_DIRTY=true
 
PROJECT = ska-mid-cbf-fhs-fsp

KUBE_NAMESPACE ?= ska-mid-cbf## KUBE_NAMESPACE defines the Kubernetes Namespace that will be deployed to using Helm
SDP_KUBE_NAMESPACE ?= ska-mid-cbf-sdp##namespace to be used
DASHBOARD ?= webjive-dash.dump
CLUSTER_DOMAIN ?= cluster.local
FHS_SERVER_ID ?= fhs01
CONFIG_LOCATION ?= /app/mnt/lowLevelConfigMap

HELM_RELEASE ?= test##H ELM_RELEASE is the release that all Kubernetes resources will be labelled with

OCI_IMAGES = ska-mid-cbf-fhs-fsp-corr
OCI_IMAGES_TO_PUBLISH ?= $(OCI_IMAGES)
OCI_IMAGE_BUILD_CONTEXT = $(PWD)

#HELM_CHART ?= ska-mid-cbf-fhs-corr-umbrella## HELM_CHART the chart name
K8S_CHART ?= $(HELM_CHART)
TANGO_DATABASE = tango-databaseds-$(HELM_RELEASE)
TANGO_HOST = $(TANGO_DATABASE):10000## TANGO_HOST is an input!

#K8S_UMBRELLA_CHART_PATH ?= ./charts/ska-mid-cbf-fhs-corr-umbrella

CI_REGISTRY ?= gitlab.com/ska-telescope/ska-mid-cbf-fhs-fsp

CI_PROJECT_DIR ?= .

KUBE_CONFIG_BASE64 ?=  ## base64 encoded kubectl credentials for KUBECONFIG
KUBECONFIG ?= /etc/deploy/config ## KUBECONFIG location

# this assumes host and talon board 1g ethernet is on the 192.168 subnet
#HOST_IP = $(shell ip a 2> /dev/null | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p' | grep 192.168) 
JIVE ?= false# Enable jive
TARANTA ?= false# Enable Taranta
MINIKUBE ?= false ## Minikube or not
K3D ?= false ## K3D or not
EXPOSE_All_DS ?= true ## Expose All Tango Services to the external network (enable Loadbalancer service)
SKA_TANGO_OPERATOR ?= false
ITANGO_ENABLED ?= true## ITango enabled in ska-tango-base

TARANTA_PARAMS = --set ska-taranta.enabled=$(TARANTA) \
				 --set ska-taranta-auth.enabled=$(TARANTA) \
				 --set ska-dashboard-repo.enabled=$(TARANTA)

ifneq ($(MINIKUBE),)
ifneq ($(MINIKUBE),true)
TARANTA_PARAMS = --set ska-taranta.enabled=$(TARANTA) \
				 --set ska-taranta-auth.enabled=true \
				 --set ska-dashboard-repo.enabled=false
endif
endif


K8S_CHART_PARAMS = --set global.minikube=$(MINIKUBE) \
	--set global.k3d=$(K3D) \
	--set global.exposeAllDS=$(EXPOSE_All_DS) \
	--set global.tango_host=$(TANGO_HOST) \
	--set global.cluster_domain=$(CLUSTER_DOMAIN) \
	--set global.operator=$(SKA_TANGO_OPERATOR) \
	--set ska-tango-base.itango.enabled=$(ITANGO_ENABLED) \
	--set ska-mid-cbf-fhs-fsp.hostInfo.clusterDomain=$(CLUSTER_DOMAIN) \
	--set ska-mid-cbf-fhs-fsp.hostInfo.fhsServerId=$(FHS_SERVER_ID) \
	--set ska-mid-cbf-fhs-fsp.hostInfo.configLocation=$(CONFIG_LOCATION) \
	--set ska-mid-cbf-fhs-fsp.hostInfo.namespace=$(KUBE_NAMESPACE) \
	${TARANTA_PARAMS}


# W503: "Line break before binary operator." Disabled to work around a bug in flake8 where currently both "before" and "after" are disallowed.
PYTHON_SWITCHES_FOR_FLAKE8 = --ignore=DAR201,W503,E731

# F0002, F0010: Astroid errors. Not our problem.
# E1101: Class member not found. This breaks all classes with dynamic members.
PYTHON_SWITCHES_FOR_PYLINT = --disable=F0002,F0010,E1101
PYTHON_SWITCHES_FOR_PYLINT_LOCAL = --disable=F0002,F0010,E1101
PYTHON_LINE_LENGTH = 130
POETRY_PYTHON_RUNNER = poetry run python3 -m

PYTHON_LINT_TARGET = ./src/
PYTHON_VARS_AFTER_PYTEST = --forked
K8S_VARS_AFTER_PYTEST = -s

PYTHON_TEST_FILE = ./tests/

#
# include makefile to pick up the standard Make targets, e.g., 'make build'
# build, 'make push' docker push procedure, etc. The other Make targets
# ('make interactive', 'make test', etc.) are defined in this file.
#

include .make/*.mk

all: test lint

# The following steps copy across useful output to this volume which can
# then be extracted to form the CI summary for the test procedure.
test:

	 python setup.py test | tee ./build/setup_py_test.stdout; \
	 mv coverage.xml ./build/reports/code-coverage.xml;

# The following steps copy across useful output to this volume which can
# then be extracted to form the CI summary for the test procedure.
lint:

	# FIXME pylint needs to run twice since there is no way go gather the text and junit xml output at the same time
	pip3 install pylint2junit; \
	pylint --output-format=parseable src/ska/skeleton | tee ./build/code_analysis.stdout; \
	pylint --output-format=pylint2junit.JunitReporter src/ska/skeleton > ./build/reports/linting.xml;


.PHONY: all test lint

format-python:
	$(POETRY_PYTHON_RUNNER) isort --profile black --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_ISORT) $(PYTHON_LINT_TARGET)
	$(POETRY_PYTHON_RUNNER) black --exclude .+\.ipynb --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_BLACK) $(PYTHON_LINT_TARGET)

fix-python-imports:
	$(POETRY_PYTHON_RUNNER) isort --profile black --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_ISORT) $(PYTHON_LINT_TARGET)

lint-python-local:
	mkdir -p build/lint-output
	@echo "Linting..."
	-@ISORT_ERROR=0 BLACK_ERROR=0 FLAKE_ERROR=0 PYLINT_ERROR=0; \
	$(POETRY_PYTHON_RUNNER) isort --check-only --profile black --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_ISORT) $(PYTHON_LINT_TARGET) &> build/lint-output/1-isort-output.txt; \
	if [ $$? -ne 0 ]; then ISORT_ERROR=1; fi; \
	$(POETRY_PYTHON_RUNNER) black --exclude .+\.ipynb --check --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_BLACK) $(PYTHON_LINT_TARGET) &> build/lint-output/2-black-output.txt; \
	if [ $$? -ne 0 ]; then BLACK_ERROR=1; fi; \
	$(POETRY_PYTHON_RUNNER) flake8 --show-source --statistics --max-line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_FLAKE8) $(PYTHON_LINT_TARGET) &> build/lint-output/3-flake8-output.txt; \
	if [ $$? -ne 0 ]; then FLAKE_ERROR=1; fi; \
	$(POETRY_PYTHON_RUNNER) pylint --output-format=parseable --max-line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_PYLINT_LOCAL) $(PYTHON_LINT_TARGET) &> build/lint-output/4-pylint-output.txt; \
	if [ $$? -ne 0 ]; then PYLINT_ERROR=1; fi; \
	if [ $$ISORT_ERROR -ne 0 ]; then echo "Isort lint errors were found. Check build/lint-output/1-isort-output.txt for details."; fi; \
	if [ $$BLACK_ERROR -ne 0 ]; then echo "Black lint errors were found. Check build/lint-output/2-black-output.txt for details."; fi; \
	if [ $$FLAKE_ERROR -ne 0 ]; then echo "Flake8 lint errors were found. Check build/lint-output/3-flake8-output.txt for details."; fi; \
	if [ $$PYLINT_ERROR -ne 0 ]; then echo "Pylint lint errors were found. Check build/lint-output/4-pylint-output.txt for details."; fi; \
	if [ $$ISORT_ERROR -eq 0 ] && [ $$BLACK_ERROR -eq 0 ] && [ $$FLAKE_ERROR -eq 0 ] && [ $$PYLINT_ERROR -eq 0 ]; then echo "Lint was successful. Check build/lint-output for any additional details."; fi;

format-python:
	$(POETRY_PYTHON_RUNNER) isort --profile black --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_ISORT) $(PYTHON_LINT_TARGET)
	$(POETRY_PYTHON_RUNNER) black --exclude .+\.ipynb --line-length $(PYTHON_LINE_LENGTH) $(PYTHON_SWITCHES_FOR_BLACK) $(PYTHON_LINT_TARGET)
