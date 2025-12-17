# app/routes.py
"""
Маршруты приложения.
Определяют URL адреса и обработчики запросов.
"""

# Импортируем необходимые модули Flask и расширения
from flask import render_template, url_for, flash, redirect, \
    request  # Функции для работы с шаблонами, URL, сообщениями и перенаправлениями
from flask_login import login_user, current_user, logout_user, login_required  # Функции для работы с аутентификацией
from app import db, bcrypt  # Объекты базы данных и bcrypt
f"""
Маршруты приложения.
Определяют URL адреса и обработчики запросов.
"""

# Импортируем необходимые модули Flask и расширения
from flask import render_template, url_for, flash, redirect, request  # Функции для работы с шаблонами, URL, сообщениями и перенаправлениями
from flask_login import login_user, current_user, logout_user, login_required  # Функции для работы с аутентификацией
from app import db, bcrypt  # Объекты базы данных и bcrypt - ИЗМЕНИЛИ ЭТУ СТРОКУ
from app.models import User  # Модель пользователя
from app.forms import RegistrationForm, LoginForm, EditProfileForm  # Формы приложения
from datetime import datetime  # Для работы с датой и временем

# В Flask с фабрикой приложений мы используем декораторы @app.route
# Но чтобы избежать циклического импорта, мы создадим функцию для регистрации маршрутов

def register_routes(app):
    """
    Регистрирует все маршруты приложения.
    Вызывается из create_app() после создания экземпляра приложения.
    """

    @app.route('/')
    @app.route('/home')
    def home():
        """
        Обработчик главной страницы.

        Returns:
            rendered template: Шаблон home.html
        """
        return render_template('home.html', title='Главная')  # Рендерим шаблон с заголовком

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        Обработчик страницы регистрации.
        Поддерживает GET (отображение формы) и POST (обработка данных).

        Returns:
            rendered template или redirect: Зависит от метода запроса
        """
        # Если пользователь уже аутентифицирован, перенаправляем на главную
        if current_user.is_authenticated:
            flash('Вы уже вошли в систему!', 'info')  # Показываем информационное сообщение
            return redirect(url_for('home'))  # Перенаправляем на главную страницу

        form = RegistrationForm()  # Создаем экземпляр формы регистрации

        # Если форма отправлена и прошла валидацию
        if form.validate_on_submit():
            # Хешируем пароль с помощью bcrypt
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # Создаем нового пользователя
            user = User(
                username=form.username.data,  # Имя пользователя из формы
                email=form.email.data,  # Email из формы
                password_hash=hashed_password  # Хеш пароля
            )

            # Добавляем пользователя в сессию базы данных
            db.session.add(user)
            # Сохраняем изменения в базе данных
            db.session.commit()

            # Показываем сообщение об успехе
            flash(f'Аккаунт создан для {form.username.data}! Теперь вы можете войти.', 'success')
            # Перенаправляем на страницу входа
            return redirect(url_for('login'))

        # Рендерим шаблон с формой (для GET запроса или если форма не прошла валидацию)
        return render_template('register.html', title='Регистрация', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Обработчик страницы входа.
        Поддерживает GET (отображение формы) и POST (обработка данных).

        Returns:
            rendered template или redirect: Зависит от метода запроса
        """
        # Если пользователь уже аутентифицирован, перенаправляем на главную
        if current_user.is_authenticated:
            flash('Вы уже вошли в систему!', 'info')  # Показываем информационное сообщение
            return redirect(url_for('home'))  # Перенаправляем на главную страницу

        form = LoginForm()  # Создаем экземпляр формы входа

        # Если форма отправлена и прошла валидацию
        if form.validate_on_submit():
            # Ищем пользователя по email
            user = User.query.filter_by(email=form.email.data).first()

            # Проверяем, существует ли пользователь и верен ли пароль
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Выполняем вход пользователя
                login_user(user, remember=True)  # remember=True для длительной сессии

                # Показываем сообщение об успехе
                flash('Вы успешно вошли в систему!', 'success')

                # Перенаправляем на следующую страницу или на главную
                next_page = request.args.get('next')  # Получаем страницу для перенаправления
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                # Если аутентификация не удалась, показываем ошибку
                flash('Вход не выполнен. Проверьте email и пароль.', 'danger')

        # Рендерим шаблон с формой
        return render_template('login.html', title='Вход', form=form)

    @app.route('/logout')
    def logout():
        """
        Обработчик выхода из системы.

        Returns:
            redirect: Перенаправление на главную страницу
        """
        logout_user()  # Выход пользователя
        flash('Вы вышли из системы.', 'info')  # Показываем информационное сообщение
        return redirect(url_for('home'))  # Перенаправляем на главную страницу

    @app.route('/account')
    @login_required  # Требует аутентификации пользователя
    def account():
        """
        Обработчик страницы аккаунта пользователя.
        Доступна только аутентифицированным пользователям.

        Returns:
            rendered template: Шаблон account.html с данными пользователя
        """
        return render_template('account.html', title='Аккаунт', user=current_user)  # Рендерим шаблон с данными пользователя

    @app.route('/edit_profile', methods=['GET', 'POST'])
    @login_required  # Требует аутентификации пользователя
    def edit_profile():
        """
        Обработчик страницы редактирования профиля.
        Поддерживает GET (отображение формы) и POST (обработка данных).

        Returns:
            rendered template или redirect: Зависит от метода запроса
        """
        # Создаем экземпляр формы редактирования профиля
        # Передаем текущие имя и email пользователя для валидации
        form = EditProfileForm(
            original_username=current_user.username,  # Текущее имя пользователя
            original_email=current_user.email  # Текущий email пользователя
        )

        # Если форма отправлена и прошла валидацию
        if form.validate_on_submit():
            # Проверяем текущий пароль
            if bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
                # Обновляем данные пользователя
                current_user.username = form.username.data  # Новое имя пользователя
                current_user.email = form.email.data  # Новый email

                # Если указан новый пароль, обновляем его
                if form.new_password.data:
                    # Хешируем новый пароль
                    current_user.password_hash = bcrypt.generate_password_hash(
                        form.new_password.data
                    ).decode('utf-8')

                # Сохраняем изменения в базе данных
                db.session.commit()

                # Показываем сообщение об успехе
                flash('Ваш профиль был обновлен!', 'success')
                # Перенаправляем на страницу аккаунта
                return redirect(url_for('account'))
            else:
                # Если текущий пароль неверен, показываем ошибку
                flash('Неверный текущий пароль.', 'danger')

        # Для GET запроса предзаполняем форму текущими данными
        elif request.method == 'GET':
            form.username.data = current_user.username  # Текущее имя пользователя
            form.email.data = current_user.email  # Текущий email

        # Рендерим шаблон с формой
        return render_template('edit_profile.html', title='Редактировать профиль', form=form)

    return app  # Возвращаем приложение с зарегистрированными маршрутами
