# app/forms.py
"""
Формы приложения.
Создаются с использованием Flask-WTF для валидации и защиты от CSRF.
"""

# Импортируем необходимые классы и валидаторы
from flask_wtf import FlaskForm  # Базовый класс для форм
from wtforms import StringField, PasswordField, SubmitField  # Типы полей формы
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError  # Валидаторы полей
from app.models import User  # Модель пользователя для проверки уникальности
from app import bcrypt  # Для проверки текущего пароля
from flask_login import current_user  # Текущий аутентифицированный пользователь


class RegistrationForm(FlaskForm):
    """
    Форма регистрации нового пользователя.
    """

    # Поле для имени пользователя с валидацией
    username = StringField('Имя пользователя',
                           validators=[
                               DataRequired(message='Имя пользователя обязательно'),  # Проверка на пустое значение
                               Length(min=2, max=20, message='Имя должно быть от 2 до 20 символов')  # Проверка длины
                           ])

    # Поле для email с валидацией
    email = StringField('Email',
                        validators=[
                            DataRequired(message='Email обязателен'),  # Проверка на пустое значение
                            Email(message='Введите корректный email')  # Проверка формата email
                        ])

    # Поле для пароля с валидацией
    password = PasswordField('Пароль',
                             validators=[
                                 DataRequired(message='Пароль обязателен')  # Проверка на пустое значение
                             ])

    # Поле для подтверждения пароля
    confirm_password = PasswordField('Подтвердите пароль',
                                     validators=[
                                         DataRequired(message='Подтверждение пароля обязательно'),
                                         # Проверка на пустое значение
                                         EqualTo('password', message='Пароли должны совпадать')
                                         # Сравнение с полем password
                                     ])

    # Кнопка отправки формы
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        """
        Кастомный валидатор для проверки уникальности имени пользователя.

        Args:
            username (StringField): Поле с именем пользователя

        Raises:
            ValidationError: Если имя пользователя уже занято
        """
        # Ищем пользователя с таким же именем в базе
        user = User.query.filter_by(username=username.data).first()
        if user:
            # Если пользователь найден, генерируем ошибку валидации
            raise ValidationError('Это имя пользователя уже занято. Выберите другое.')

    def validate_email(self, email):
        """
        Кастомный валидатор для проверки уникальности email.

        Args:
            email (StringField): Поле с email

        Raises:
            ValidationError: Если email уже используется
        """
        # Ищем пользователя с таким же email в базе
        user = User.query.filter_by(email=email.data).first()
        if user:
            # Если email найден, генерируем ошибку валидации
            raise ValidationError('Этот email уже используется. Используйте другой email.')


class LoginForm(FlaskForm):
    """
    Форма входа в систему.
    """

    # Поле для email
    email = StringField('Email',
                        validators=[
                            DataRequired(message='Email обязателен'),  # Проверка на пустое значение
                            Email(message='Введите корректный email')  # Проверка формата email
                        ])

    # Поле для пароля
    password = PasswordField('Пароль',
                             validators=[
                                 DataRequired(message='Пароль обязателен')  # Проверка на пустое значение
                             ])

    # Кнопка отправки формы
    submit = SubmitField('Войти')


class EditProfileForm(FlaskForm):
    """
    Форма редактирования профиля пользователя.
    Позволяет изменить имя пользователя, email и пароль.
    """

    # Поле для нового имени пользователя
    username = StringField('Новое имя пользователя',
                           validators=[
                               DataRequired(message='Имя пользователя обязательно'),  # Проверка на пустое значение
                               Length(min=2, max=20, message='Имя должно быть от 2 до 20 символов')  # Проверка длины
                           ])

    # Поле для нового email
    email = StringField('Новый Email',
                        validators=[
                            DataRequired(message='Email обязателен'),  # Проверка на пустое значение
                            Email(message='Введите корректный email')  # Проверка формата email
                        ])

    # Поле для текущего пароля (обязательно для подтверждения изменений)
    current_password = PasswordField('Текущий пароль',
                                     validators=[
                                         DataRequired(message='Текущий пароль обязателен для подтверждения изменений')
                                         # Проверка на пустое значение
                                     ])

    # Поле для нового пароля (не обязательно)
    new_password = PasswordField('Новый пароль (оставьте пустым, если не хотите менять)',
                                 validators=[
                                     Length(min=6, message='Пароль должен быть не менее 6 символов')
                                     # Проверка минимальной длины
                                 ])

    # Поле для подтверждения нового пароля
    confirm_new_password = PasswordField('Подтвердите новый пароль',
                                         validators=[
                                             EqualTo('new_password', message='Пароли должны совпадать')
                                             # Сравнение с полем new_password
                                         ])

    # Кнопка отправки формы
    submit = SubmitField('Обновить профиль')

    def __init__(self, original_username, original_email, *args, **kwargs):
        """
        Конструктор формы с сохранением оригинальных данных пользователя.

        Args:
            original_username (str): Текущее имя пользователя
            original_email (str): Текущий email пользователя
            *args, **kwargs: Аргументы родительского класса
        """
        super(EditProfileForm, self).__init__(*args, **kwargs)  # Вызываем конструктор родительского класса
        self.original_username = original_username  # Сохраняем оригинальное имя
        self.original_email = original_email  # Сохраняем оригинальный email

    def validate_username(self, username):
        """
        Кастомный валидатор для проверки уникальности нового имени пользователя.
        Пропускает валидацию, если имя не изменилось.

        Args:
            username (StringField): Поле с именем пользователя

        Raises:
            ValidationError: Если имя пользователя уже занято другим пользователем
        """
        # Проверяем, изменилось ли имя пользователя
        if username.data != self.original_username:
            # Ищем пользователя с таким же именем в базе
            user = User.query.filter_by(username=username.data).first()
            if user:
                # Если пользователь найден, генерируем ошибку валидации
                raise ValidationError('Это имя пользователя уже занято. Выберите другое.')

    def validate_email(self, email):
        """
        Кастомный валидатор для проверки уникальности нового email.
        Пропускает валидацию, если email не изменился.

        Args:
            email (StringField): Поле с email

        Raises:
            ValidationError: Если email уже используется другим пользователем
        """
        # Проверяем, изменился ли email
        if email.data != self.original_email:
            # Ищем пользователя с таким же email в базе
            user = User.query.filter_by(email=email.data).first()
            if user:
                # Если email найден, генерируем ошибку валидации
                raise ValidationError('Этот email уже используется. Используйте другой email.')

    def validate_current_password(self, current_password):
        """
        Кастомный валидатор для проверки текущего пароля.

        Args:
            current_password (PasswordField): Поле с текущим паролем

        Raises:
            ValidationError: Если текущий пароль неверен
        """
        # Проверяем, соответствует ли введенный пароль хешу в базе
        if not bcrypt.check_password_hash(current_user.password_hash, current_password.data):
            # Если пароль неверен, генерируем ошибку валидации
            raise ValidationError('Неверный текущий пароль.')
