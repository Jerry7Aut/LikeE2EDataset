# security_gateway — 唯一策略执行点（数据面）+ 蓝队受控 API（管理面）
# 仅标准库，无第三方依赖。
FROM python:3.11-slim

WORKDIR /app
COPY gateway.py /app/gateway.py
COPY rules.example.json /app/rules.example.json

RUN mkdir -p /data

EXPOSE 80 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/_health',timeout=2)" || exit 1

CMD ["python", "-u", "/app/gateway.py"]
