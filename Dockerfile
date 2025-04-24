FROM python:3.9-slim

# Устанавливаем системные зависимости
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем зависимости отдельно для кэширования
COPY app/requirements.txt .

# Устанавливаем Python зависимости (включая gunicorn)
RUN pip install --no-cache-dir gunicorn==21.2.0 && \
    pip install --no-cache-dir -r requirements.txt

# Проверяем что gunicorn установлен
RUN which gunicorn

# Копируем остальное приложение
COPY . .

EXPOSE 5000

# Альтернативная команда запуска с полным путем
CMD ["/usr/local/bin/gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app.app:app"]