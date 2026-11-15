# ndr — 旁路网络检测与响应组件（镜像投递）
# 仅标准库，无第三方依赖。
FROM python:3.11-slim

WORKDIR /app
COPY ndr.py /app/ndr.py

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=12 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/_health',timeout=2)" || exit 1

CMD ["python", "-u", "/app/ndr.py"]
