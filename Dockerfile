# انتخاب یک تصویر پایه
FROM python:3.8-slim

# تنظیم دایرکتوری کاری
WORKDIR /.

# کپی فایل‌های مورد نیاز برای نصب وابستگی‌ها
COPY requirements.txt .

# نصب وابستگی‌های پایتون
RUN pip install -r requirements.txt

# کپی تمام فایل‌های پروژه به داخل تصویر
COPY . .

# تعریف پورتی که توسط اپلیکیشن استفاده می‌شود
EXPOSE 5000

# دستور برای اجرای اپلیکیشن فلاسک
CMD ["python", "server.py"]
