# استفاده از نسخه اخیر Node.js
FROM node:latest

# تنظیم دایرکتوری کاری
WORKDIR /.

# کپی کردن فایل‌های package.json و package-lock.json
COPY package*.json ./

# نصب وابستگی‌ها
RUN npm install

# کپی کردن تمام فایل‌های پروژه
COPY . .

#port
EXPOSE 3000

# دستور برای اجرای اپلیکیشن
CMD ["npm", "start"]
