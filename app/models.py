# app/models.py
"""
Модели базы данных.
Определяют структуру таблиц и отношения между ними.
"""

# Импортируем объекты из __init__.py
from app import db, login_manager  # Объекты базы данных и менеджера аутентификации
from flask_login import UserMixin  # Миксин для пользователя Flask-Login
from datetime import datetime  # Для работы с датами и временем


@login_manager.user_loader
def load_user(user_id):
    """
    Callback-функция для Flask-Login.
    Загружает пользователя по ID из базы данных.

    Args:
        user_id (int): ID пользователя

    Returns:
        User: Объект пользователя или None если не найден
    """
    return User.query.get(int(user_id))  # Ищем пользователя по первичному ключу


class User(db.Model, UserMixin):
    """
    Модель пользователя.
    Хранит информацию о пользователе: имя, email, пароль и дату регистрации.
    Наследуется от db.Model (SQLAlchemy) и UserMixin (Flask-Login).
    """

    # Поля таблицы пользователей
    id = db.Column(db.Integer, primary_key=True)  # Первичный ключ, автоинкремент
    username = db.Column(db.String(20), unique=True, nullable=False)  # Имя пользователя (уникальное)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email (уникальный)
    password_hash = db.Column(db.String(128), nullable=False)  # Хеш пароля
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Дата создания записи

    def __repr__(self):
        """
        Строковое представление объекта пользователя.
        Используется для отладки.

        Returns:
            str: Строка с информацией о пользователе
        """
        return f"User('{self.username}', '{self.email}')"

    @property
    def password(self):
        """
        Свойство password.
        Запрещает прямое чтение пароля.

        Raises:
            AttributeError: При попытке чтения пароля
        """
        raise AttributeError('Пароль не доступен для чтения')

    @password.setter
    def password(self, password):
        """
        Сеттер для пароля.
        Автоматически хеширует пароль при установке.

        Args:
            password (str): Пароль в открытом виде
        """
        # Генерируем хеш пароля с помощью bcrypt
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        """
        Проверяет, соответствует ли переданный пароль хешу в базе.

        Args:
            password (str): Пароль для проверки

        Returns:
            bool: True если пароль верный, иначе False
        """
        return bcrypt.check_password_hash(self.password_hash, password)
