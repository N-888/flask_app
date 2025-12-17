"""
Основной файл инициализации приложения Flask.
Содержит конфигурацию приложения, инициализацию расширений
и подключение маршрутов.
"""

import os
# Импортируем необходимые модули Flask
from flask import Flask  # Flask - основной класс приложения
from flask_sqlalchemy import SQLAlchemy  # ORM для работы с базой данных
from flask_bcrypt import Bcrypt  # Для хеширования паролей
from flask_login import LoginManager  # Для управления сессиями пользователей
from flask_mail import Mail  # Для отправки email уведомлений (опционально)


# Создаем экземпляры расширений (пока без приложения)
db = SQLAlchemy()  # Объект для работы с базой данных
bcrypt = Bcrypt()  # Объект для хеширования паролей
login_manager = LoginManager()  # Объект для управления аутентификацией
mail = Mail()  # Объект для отправки почты


def create_app():
    """
    Фабричная функция для создания приложения Flask.
    Позволяет создавать несколько экземпляров приложения с разными конфигурациями.
    """
    # Создаем экземпляр приложения Flask
    app = Flask(__name__)

    # Конфигурация приложения
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-key-for-dev') # ← ВАШ КЛЮЧ ЗДЕСЬ. Секретный ключ для защиты от CSRF атак
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Путь к базе данных SQLite
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Отключаем сигналы изменения объектов

    # Настройки для отправки email (если потребуется для восстановления пароля)
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # SMTP сервер
    app.config['MAIL_PORT'] = 587  # Порт SMTP
    app.config['MAIL_USE_TLS'] = True  # Использовать TLS шифрование
    # Закомментируйте или раскомментируйте следующие 2 строки по необходимости
    # app.config['MAIL_USERNAME'] = 'ваш-email@gmail.com'  # ← ЗАКОММЕНТИРОВАНО  # Ваш email
    # app.config['MAIL_PASSWORD'] = 'ваш-пароль'  # ← ЗАКОММЕНТИРОВАНО  # Пароль от email

    # Инициализируем расширения с приложением
    db.init_app(app)  # Подключаем базу данных к приложению
    bcrypt.init_app(app)  # Подключаем Bcrypt к приложению
    login_manager.init_app(app)  # Подключаем LoginManager к приложению
    mail.init_app(app)  # Подключаем Mail к приложению

    # Настраиваем LoginManager
    login_manager.login_view = 'login'  # Маршрут для страницы входа
    login_manager.login_message_category = 'info'  # Категория сообщения при перенаправлении

    # Импортируем модели и маршруты после создания приложения
    # чтобы избежать циклических импортов
    from app.models import User  # Модель пользователя

    # Создаем таблицы в базе данных при запуске приложения
    with app.app_context():
        db.create_all()  # Создаем все таблицы, определенные в моделях

    # Регистрируем маршруты приложения
    from app.routes import register_routes
    app = register_routes(app)  # Регистрируем все маршруты

    return app  # Возвращаем созданное приложение

