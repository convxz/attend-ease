const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');

// Подключение к MongoDB
mongoose.connect('mongodb://localhost:27017/auth-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Ошибка подключения к MongoDB:'));
db.once('open', () => {
  console.log('Подключение к MongoDB установлено.');
});

// Схема пользователя
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

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
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: 'Неверное имя пользователя.' });
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
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
    const user = await User.findById(id);
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
app.get('/register', (req, res) => {
  res.render('register'); // Рендерим register.ejs
});

app.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
      res.render('register', { message: 'Пользователь с таким именем уже существует.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, passwordHash });

    await newUser.save();

    // После сохранения пользователя авторизуем его
    req.login(newUser, (err) => {
      if (err) {
        return next(err);
      }
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
