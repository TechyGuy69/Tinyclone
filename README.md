# 🚀 TinyClone – PHP URL Shortener

A lightweight, **all-in-one PHP URL Shortener**, inspired by TinyURL/Bitly — built using **pure PHP + SQLite**, and works **without any Apache rewrite rules**.

---

## ✨ Features

- 🔗 **Create short URLs**
- 🆔 **Custom alias support**
- 📊 **Click tracking**
  - **IP address**
  - **User agent**
  - **Device type** (Mobile / Desktop / Tablet)
  - **Referrer**
  - **Timestamp**
- 🌍 **Country analytics** (IP-based lookup)
- 📱 **Automatic QR Code generation**
- 🔐 **Admin dashboard** to view links & clicks
- ⚡ **No .htaccess required** — works using `?r=alias` fallback
- 📦 **Single PHP file** (easy to deploy anywhere)

---

## 🛠 Tech Stack

- **PHP 8+**
- **SQLite** (auto-created)
- **Vanilla HTML/CSS**
- **External QR provider** → `api.qrserver.com`

---

## 📥 Installation

1. Download the file:  
   **`tinyclone.php`**

2. Place it inside your server’s webroot:  
C:\xampp\htdocs\

nginx
Copy code
or  
/var/www/html/

markdown
Copy code

3. Open in the browser:
http://localhost/tinyclone.php

yaml
Copy code

4. Start creating short URLs!

---

## 🎯 Why This Project?

This project is great for learning:

- **Routing & redirects**
- **URL shortening logic**
- **Database handling**
- **Analytics & tracking**
- **Security basics (admin auth, CSRF)**
- **Clean backend architecture in PHP**

---

## 📄 License

Free to use, modify, and improve.

---
