const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const { Pool } = require('pg');



const { Pool } = require('pg');

// Создаем подключение к PostgreSQL
const pool = new Pool({
  user: 'myuser',           // Имя пользователя PostgreSQL
  host: 'localhost',        // Хост
  database: 'mydatabase',   // Имя базы данных
  password: 'mypassword',   // Пароль
  port: 5432,               // Порт (по умолчанию 5432)
});

// Пример создания таблицы для пользователей (выполните один раз в консоли PostgreSQL)
const createUserTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      passwordHash VARCHAR(255) NOT NULL
    );
  `;
  await pool.query(query);
};

// Вызовите createUserTable один раз, чтобы создать таблицу в базе данных.
createUserTable();

// Настройка приложения
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs'); // Устанавливаем EJS как шаблонизатор
app.set('views', path.join(__dirname, 'views')); // Папка для шаблонов
app.use(express.static(path.join(__dirname, 'public'))); // Подключаем статические файлы
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Настройка стратегии Passport
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // Ищем пользователя в базе данных PostgreSQL
      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      const user = result.rows[0];

      if (!user) {
        return done(null, false, { message: 'Неверное имя пользователя.' });
      }

      // Сравниваем пароли
      const isMatch = await bcrypt.compare(password, user.passwordhash);
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Неверный пароль.' });
      }
    } catch (err) {
      return done(err);
    }
  })
);


passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});


// Маршруты
app.get('/', (req, res) => {
  res.render('index');
});

// Рендеринг формы входа
app.get('/login', (req, res) => {
  res.render('login'); // Рендерим login.ejs
});

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
  })
);


// Рендеринг формы регистрации
app.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Проверяем, существует ли уже пользователь с таким именем
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      res.render('register', { message: 'Пользователь с таким именем уже существует.' });
      return;
    }

    // Хешируем пароль
    const passwordHash = await bcrypt.hash(password, 10);

    // Сохраняем нового пользователя
    await pool.query('INSERT INTO users (username, passwordhash) VALUES ($1, $2)', [username, passwordHash]);

    // Автоматически авторизуем пользователя после регистрации
    const newUser = { username, passwordHash };
    req.login(newUser, (err) => {
      if (err) return next(err);
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error(err);
    res.send('Ошибка регистрации.');
  }
});



app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(
      `<h1>Добро пожаловать, ${req.user.username}!</h1><a href="/logout">Выйти</a>`
    );
  } else {
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error(err);
    res.redirect('/');
  });
});


// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});
