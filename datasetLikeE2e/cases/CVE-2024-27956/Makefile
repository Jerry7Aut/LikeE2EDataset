# <CASE_ID> —— 评测入口（qrj 框架，模板）
PYTHON ?= python
RUNNER = ../../run.py
EVAL   = ../../evaluator/generic_env.py

.PHONY: help full calibrate down

help:
	@echo "<CASE_ID> —— qrj 评测入口"
	@echo "  make full       正式评测（= python ../../run.py --case <CASE_ID>）"
	@echo "  make calibrate  参考标定（= python ../../evaluator/generic_env.py --case-dir . --calibrate）"
	@echo "  make down       停止并清理黑盒容器"

full:
	$(PYTHON) $(RUNNER) --case <CASE_ID>

calibrate:
	$(PYTHON) $(EVAL) --case-dir . --calibrate

down:
	docker compose -f blackbox/docker-compose.yml down
