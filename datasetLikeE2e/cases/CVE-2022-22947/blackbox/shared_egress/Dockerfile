# shared_egress — 透明 TCP 共享出口
# 无第三方依赖，仅标准库 asyncio。
FROM python:3.11-slim

WORKDIR /app
COPY proxy.py /app/proxy.py

EXPOSE 80

CMD ["python", "-u", "/app/proxy.py"]
