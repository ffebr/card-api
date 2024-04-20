// authRouter.js
/*
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dbConnection = require('./db');

// Функция для создания JWT токена
function generateToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, '224455', { expiresIn: '1h' });
}

// Регистрация нового пользователя
router.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Необходимо указать имя пользователя и пароль' });
        }

        // Проверка, существует ли пользователь с таким именем
        dbConnection.query('SELECT * FROM users WHERE email = ?', [username], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
            }

            // Хэширование пароля
            const hashedPassword = await bcrypt.hash(password, 10);

            // Получение текущей даты и времени в формате MySQL
            const registrationDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

            // Вставка нового пользователя в базу данных
            dbConnection.query('INSERT INTO users (email, password, registration_date) VALUES (?, ?, ?)', [username, hashedPassword, registrationDate], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });
            });
        });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});



// Вход пользователя и создание JWT токена
router.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Необходимо указать имя пользователя и пароль' });
        }

        // Поиск пользователя в базе данных
        dbConnection.query('SELECT * FROM users WHERE email = ?', [username], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            // Проверка, найден ли пользователь
            if (results.length === 0) {
                return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }

            // Сравнение паролей
            const user = results[0];
            if (await bcrypt.compare(password, user.password)) {
                // Создание JWT токена
                const token = generateToken(user);
                res.json({ token });
            } else {
                res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});


// Защищенный маршрут для проверки JWT токена
router.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Это защищенный маршрут', user: req.user });
});

// Промежуточное ПО для проверки JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется токен авторизации' });
    }

    jwt.verify(token, '224455', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Неверный токен авторизации' });
        }
        req.user = user;
        next();
    });
}

module.exports = router;
*/