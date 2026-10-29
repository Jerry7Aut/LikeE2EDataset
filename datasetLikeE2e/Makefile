# datasetLikeE2e —— 顶层命令入口（语法糖，实际调 run.py）
.PHONY: all run case components help

all: run

run:
	python run.py --all

case:
	python run.py --case $(CASE)

# 公用镜像（所有 case 共用）：改 components/ 后重建，再回归标定受影响的 case
components:
	docker build -t datasetlikee2e/ndr:1 components/ndr
	docker build -t datasetlikee2e/policy-gateway:1 components/security_gateway
	docker build -t datasetlikee2e/transparent-proxy:1 components/transparent_proxy
	docker build -t datasetlikee2e/runner:1 components/runner

help:
	@echo "make run             跑 cases/ 下全部样例（= make all）"
	@echo "make case CASE=<id>  跑单个样例，例如 make case CASE=CVE-2025-24928"
	@echo "make components      重建公用镜像（ndr / policy-gateway / transparent-proxy / runner）"
